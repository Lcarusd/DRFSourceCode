"""
提供一个APIView类，它是REST框架中所有视图的基础。
"""
from __future__ import unicode_literals

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db import connection, models, transaction
from django.http import Http404
from django.http.response import HttpResponseBase
from django.utils import six
from django.utils.cache import cc_delim_re, patch_vary_headers
from django.utils.encoding import smart_text
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View

from rest_framework import exceptions, status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.schemas import DefaultSchema
from rest_framework.settings import api_settings
from rest_framework.utils import formatting


def get_view_name(view_cls, suffix=None):
    """
    给定一个视图类，返回一个文本名称来表示视图。
    该名称用于可浏览的API和OPTIONS响应中。
    该函数是"VIEW_NAME_FUNCTION"设置的默认值。
    """
    name = view_cls.__name__
    name = formatting.remove_trailing_string(name, 'View')
    name = formatting.remove_trailing_string(name, 'ViewSet')
    name = formatting.camelcase_to_spaces(name)
    if suffix:
        name += ' ' + suffix

    return name


def get_view_description(view_cls, html=False):
    """
    给定一个视图类，返回一个文本描述来表示视图。
    该名称用于可浏览的API和OPTIONS响应中。
    该函数是"VIEW_NAME_FUNCTION"设置的默认值。
    """
    description = view_cls.__doc__ or ''
    description = formatting.dedent(smart_text(description))
    if html:
        return formatting.markup_description(description)
    return description


def set_rollback():
    atomic_requests = connection.settings_dict.get('ATOMIC_REQUESTS', False)
    if atomic_requests and connection.in_atomic_block:
        transaction.set_rollback(True)


def exception_handler(exc, context):
    """
    返回应该用于任何设定例外的响应。

    默认情况下，我们处理REST框架`APIException`，
    以及Django内置的`Http404`和`PermissionDenied`异常。

    任何未处理的异常可能会返回`None`，这会引发500错误。
    """
    if isinstance(exc, exceptions.APIException):
        headers = {}
        if getattr(exc, 'auth_header', None):
            headers['WWW-Authenticate'] = exc.auth_header
        if getattr(exc, 'wait', None):
            headers['Retry-After'] = '%d' % exc.wait

        if isinstance(exc.detail, (list, dict)):
            data = exc.detail
        else:
            data = {'detail': exc.detail}

        set_rollback()
        return Response(data, status=exc.status_code, headers=headers)

    elif isinstance(exc, Http404):
        msg = _('Not found.')
        data = {'detail': six.text_type(msg)}

        set_rollback()
        return Response(data, status=status.HTTP_404_NOT_FOUND)

    elif isinstance(exc, PermissionDenied):
        msg = _('Permission denied.')
        data = {'detail': six.text_type(msg)}

        set_rollback()
        return Response(data, status=status.HTTP_403_FORBIDDEN)

    return None


class APIView(View):

    # 以下策略可以在全局或按视图设置。
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES
    parser_classes = api_settings.DEFAULT_PARSER_CLASSES
    authentication_classes = api_settings.DEFAULT_AUTHENTICATION_CLASSES
    throttle_classes = api_settings.DEFAULT_THROTTLE_CLASSES
    permission_classes = api_settings.DEFAULT_PERMISSION_CLASSES
    content_negotiation_class = api_settings.DEFAULT_CONTENT_NEGOTIATION_CLASS
    metadata_class = api_settings.DEFAULT_METADATA_CLASS
    versioning_class = api_settings.DEFAULT_VERSIONING_CLASS

    # 允许依赖注入其他设置以使测试更容易。
    settings = api_settings

    schema = DefaultSchema()

    @classmethod
    def as_view(cls, **initkwargs):
        """
        将原始类存储在视图函数中。

        这使我们能够在进行URL反向查找时发现有关视图的信息。
        用于breadcrumb生成。
        """
        if isinstance(getattr(cls, 'queryset', None), models.query.QuerySet):
            def force_evaluation():
                raise RuntimeError(
                    'Do not evaluate the `.queryset` attribute directly, '
                    'as the result will be cached and reused between requests. '
                    'Use `.all()` or call `.get_queryset()` instead.'
                )
            cls.queryset._fetch_all = force_evaluation

        view = super(APIView, cls).as_view(**initkwargs)
        view.cls = cls
        view.initkwargs = initkwargs

        # 注意：基于会话的认证是明确的CSRF验证，所有其他认证都是CSRF豁免。
        return csrf_exempt(view)

    @property
    def allowed_methods(self):
        """
        在公共属性中将Django的私有`_allowed_methods`接口封装起来。
        """
        return self._allowed_methods()

    @property
    def default_response_headers(self):
        headers = {
            'Allow': ', '.join(self.allowed_methods),
        }
        if len(self.renderer_classes) > 1:
            headers['Vary'] = 'Accept'
        return headers

    def http_method_not_allowed(self, request, *args, **kwargs):
        """
        如果`request.method`不对应于一个处理程序方法，请确定要引发的异常类型。
        """
        raise exceptions.MethodNotAllowed(request.method)

    def permission_denied(self, request, message=None):
        """
        如果请求不被允许，请确定要提出什么样的例外。
        """
        if request.authenticators and not request.successful_authenticator:
            raise exceptions.NotAuthenticated()
        raise exceptions.PermissionDenied(detail=message)

    def throttled(self, request, wait):
        """
        如果请求受到限制，请确定要引发的异常类型。
        """
        raise exceptions.Throttled(wait)

    def get_authenticate_header(self, request):
        """
        如果请求未经身份验证，请确定要用于401响应的WWW-Authenticate标头（如果有）。
        """
        authenticators = self.get_authenticators()
        if authenticators:
            return authenticators[0].authenticate_header(request)

    def get_parser_context(self, http_request):
        """
        返回一个传递给Parser.parse（）的字典，作为`parser_context`关键字参数。
        """
        # 注意：另外`request`和`encoding`也将被Request对象添加到上下文中。
        return {
            'view': self,
            'args': getattr(self, 'args', ()),
            'kwargs': getattr(self, 'kwargs', {})
        }

    def get_renderer_context(self):
        """
        返回一个传递给Renderer.render（）的字典，作为`renderer_context`关键字参数。
        """
        # 注意：另外'response'也将通过Response对象添加到上下文中。
        return {
            'view': self,
            'args': getattr(self, 'args', ()),
            'kwargs': getattr(self, 'kwargs', {}),
            'request': getattr(self, 'request', None)
        }

    def get_exception_handler_context(self):
        """
        返回一个传递给EXCEPTION_HANDLER的字典，作为`context`参数。
        """
        return {
            'view': self,
            'args': getattr(self, 'args', ()),
            'kwargs': getattr(self, 'kwargs', {}),
            'request': getattr(self, 'request', None)
        }

    def get_view_name(self):
        """
        返回在OPTIONS响应和可浏览API中使用的视图名称。
        """
        func = self.settings.VIEW_NAME_FUNCTION
        return func(self.__class__, getattr(self, 'suffix', None))

    def get_view_description(self, html=False):
        """
        返回视图的一些描述性文本，如OPTIONS响应和可浏览的API中所使用的。
        """
        func = self.settings.VIEW_DESCRIPTION_FUNCTION
        return func(self.__class__, html)

    # API策略实例化方法

    def get_format_suffix(self, **kwargs):
        """
        确定request是否包含'.json'风格格式后缀
        """
        if self.settings.FORMAT_SUFFIX_KWARG:
            return kwargs.get(self.settings.FORMAT_SUFFIX_KWARG)

    def get_renderers(self):
        """
        实例化并返回该视图可以使用的渲染器列表。
        """
        return [renderer() for renderer in self.renderer_classes]

    def get_parsers(self):
        """
        实例化并返回此视图可以使用的解析器列表。
        """
        return [parser() for parser in self.parser_classes]

    def get_authenticators(self):
        """
        实例化并返回此视图可以使用的验证器列表。
        """
        return [auth() for auth in self.authentication_classes]

    def get_permissions(self):
        """
        实例化并返回此视图所需的权限列表。
        """
        return [permission() for permission in self.permission_classes]

    def get_throttles(self):
        """
        实例化并返回此视图使用的节流列表。
        """
        return [throttle() for throttle in self.throttle_classes]

    def get_content_negotiator(self):
        """
        实例化并返回要使用的内容协商类。
        """
        if not getattr(self, '_negotiator', None):
            self._negotiator = self.content_negotiation_class()
        return self._negotiator

    def get_exception_handler(self):
        """
        返回此视图使用的异常处理程序。
        """
        return self.settings.EXCEPTION_HANDLER

    # API policy implementation methods

    def perform_content_negotiation(self, request, force=False):
        """
        确定要使用哪个渲染器和媒体类型渲染响应。
        """
        renderers = self.get_renderers()
        conneg = self.get_content_negotiator()

        try:
            return conneg.select_renderer(request, renderers, self.format_kwarg)
        except Exception:
            if force:
                return (renderers[0], renderers[0].media_type)
            raise

    def perform_authentication(self, request):
        """
        对传入的请求执行身份验证。

        请注意，如果你重写了这个，并简单地'pass'，那么认证将会延迟执行，
        这是第一次访问`request.user`或`request.auth`。
        """
        request.user

    def check_permissions(self, request):
        """
        检查是否允许请求。
        如果请求不被允许，引发适当的异常。
        """
        for permission in self.get_permissions():
            if not permission.has_permission(request, self):
                self.permission_denied(
                    request, message=getattr(permission, 'message', None)
                )

    def check_object_permissions(self, request, obj):
        """
        检查是否允许某个给定对象的请求。
        如果请求不被允许，引发适当的异常。
        """
        for permission in self.get_permissions():
            if not permission.has_object_permission(request, self, obj):
                self.permission_denied(
                    request, message=getattr(permission, 'message', None)
                )

    def check_throttles(self, request):
        """
        检查是否应该限制请求。
        如果请求受到限制，则引发适当的异常。
        """
        for throttle in self.get_throttles():
            if not throttle.allow_request(request, self):
                self.throttled(request, throttle.wait())

    def determine_version(self, request, *args, **kwargs):
        """
        如果正在使用版本控制，则确定传入请求的任何API版本。 
        Returns（version，versioning_scheme）的二元组
        """
        if self.versioning_class is None:
            return (None, None)
        scheme = self.versioning_class()
        return (scheme.determine_version(request, *args, **kwargs), scheme)

    # 调度方法

    def initialize_request(self, request, *args, **kwargs):
        """
        返回最初的请求对象。
        """
        parser_context = self.get_parser_context(request)

        return Request(
            request,
            parsers=self.get_parsers(),
            authenticators=self.get_authenticators(),
            negotiator=self.get_content_negotiator(),
            parser_context=parser_context
        )

    def initial(self, request, *args, **kwargs):
        """
        在调用方法处理程序之前运行需要发生的任何事情。
        """
        self.format_kwarg = self.get_format_suffix(**kwargs)

        # 执行内容协商并将接受的信息存储在请求中
        neg = self.perform_content_negotiation(request)
        request.accepted_renderer, request.accepted_media_type = neg

        # 如果正在使用版本控制，请确定API版本。
        version, scheme = self.determine_version(request, *args, **kwargs)
        request.version, request.versioning_scheme = version, scheme

        # 确保传入请求被允许
        self.perform_authentication(request)
        self.check_permissions(request)
        self.check_throttles(request)

    def finalize_response(self, request, response, *args, **kwargs):
        """
        返回最终的响应对象。
        """
        # 如果没有返回正确的响应，则明显地显示错误
        assert isinstance(response, HttpResponseBase), (
            'Expected a `Response`, `HttpResponse` or `HttpStreamingResponse` '
            'to be returned from the view, but received a `%s`'
            % type(response)
        )

        if isinstance(response, Response):
            if not getattr(request, 'accepted_renderer', None):
                neg = self.perform_content_negotiation(request, force=True)
                request.accepted_renderer, request.accepted_media_type = neg

            response.accepted_renderer = request.accepted_renderer
            response.accepted_media_type = request.accepted_media_type
            response.renderer_context = self.get_renderer_context()

        # Add new vary headers to the response instead of overwriting.
        vary_headers = self.headers.pop('Vary', None)
        if vary_headers is not None:
            patch_vary_headers(response, cc_delim_re.split(vary_headers))

        for key, value in self.headers.items():
            response[key] = value

        return response

    def handle_exception(self, exc):
        """
        处理发生的任何异常，通过返回适当的响应或重新提升错误。
        """
        if isinstance(exc, (exceptions.NotAuthenticated,
                            exceptions.AuthenticationFailed)):
            # WWW-Authenticate标题为401响应，否则强制为403
            auth_header = self.get_authenticate_header(self.request)

            if auth_header:
                exc.auth_header = auth_header
            else:
                exc.status_code = status.HTTP_403_FORBIDDEN

        exception_handler = self.get_exception_handler()

        context = self.get_exception_handler_context()
        response = exception_handler(exc, context)

        if response is None:
            self.raise_uncaught_exception(exc)

        response.exception = True
        return response

    def raise_uncaught_exception(self, exc):
        if settings.DEBUG:
            request = self.request
            renderer_format = getattr(request.accepted_renderer, 'format')
            use_plaintext_traceback = renderer_format not in (
                'html', 'api', 'admin')
            request.force_plaintext_errors(use_plaintext_traceback)
        raise

    # 注意：在`as_view`内，CSRF免除视图以防止在需要覆盖`dispatch`的情况下意外删除此豁免。
    def dispatch(self, request, *args, **kwargs):
        """
        `.dispatch（）`与Django的常规调度非常相似，但是有额外的启动，结束和异常处理handling。
        """
        self.args = args
        self.kwargs = kwargs
        request = self.initialize_request(request, *args, **kwargs)
        self.request = request
        self.headers = self.default_response_headers  # deprecate?

        try:
            self.initial(request, *args, **kwargs)

            # 获取适当的处理程序方法
            if request.method.lower() in self.http_method_names:
                handler = getattr(self, request.method.lower(),
                                  self.http_method_not_allowed)
            else:
                handler = self.http_method_not_allowed

            response = handler(request, *args, **kwargs)

        except Exception as exc:
            response = self.handle_exception(exc)

        self.response = self.finalize_response(
            request, response, *args, **kwargs)
        return self.response

    def options(self, request, *args, **kwargs):
        """
        HTTP'OPTIONS'请求的Handler方法。
        """
        if self.metadata_class is None:
            return self.http_method_not_allowed(request, *args, **kwargs)
        data = self.metadata_class().determine_metadata(request, self)
        return Response(data, status=status.HTTP_200_OK)
