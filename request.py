"""
Request类用作标准请求对象的包装。

包装请求后提供更丰富的API，特别是：

    - 根据Content-Type头自动解析内容，并可作为request.data使用
    - 全面支持PUT方法，包括对文件上传的支持
    - 形成HTTP方法，内容类型和内容的重载
"""
from __future__ import unicode_literals

import sys
from contextlib import contextmanager

from django.conf import settings
from django.http import HttpRequest, QueryDict
from django.http.multipartparser import parse_header
from django.http.request import RawPostDataException
from django.utils import six
from django.utils.datastructures import MultiValueDict

from rest_framework import HTTP_HEADER_ENCODING, exceptions
from rest_framework.settings import api_settings


def is_form_media_type(media_type):
    """
    如果媒体类型是有效的表单媒体类型，则返回True。
    """
    base_media_type, params = parse_header(
        media_type.encode(HTTP_HEADER_ENCODING))
    return (base_media_type == 'application/x-www-form-urlencoded' or
            base_media_type == 'multipart/form-data')


class override_method(object):
    """
    一个context管理器，临时覆盖请求上的方法，另外设置`view.request`属性。

    用法：用override方法（view，request，'POST'）作为请求：
                    ＃用`view`和`request`做参数
    """

    def __init__(self, view, request, method):
        self.view = view
        self.request = request
        self.method = method
        self.action = getattr(view, 'action', None)

    def __enter__(self):
        self.view.request = clone_request(self.request, self.method)
        # 对于视图集，我们还设置了`.action`属性。
        action_map = getattr(self.view, 'action_map', {})
        self.view.action = action_map.get(self.method.lower())
        return self.view.request

    def __exit__(self, *args, **kwarg):
        self.view.request = self.request
        self.view.action = self.action


class WrappedAttributeError(Exception):
    pass


@contextmanager
def wrap_attributeerrors():
    """
    用于重新引发身份验证过程中捕获的AttributeErrors，防止由属性访问协议处理这些错误。
    """
    try:
        yield
    except AttributeError:
        info = sys.exc_info()
        exc = WrappedAttributeError(str(info[1]))
        six.reraise(type(exc), exc, info[2])


class Empty(object):
    """
    未设置属性的占位符。
    不能使用'None'，因为这可能是一个有效的值。
    """
    pass


def _hasattr(obj, name):
    return not getattr(obj, name) is Empty


def clone_request(request, method):
    """
    克隆请求的内部帮助方法，用其他HTTP方法替换。 用于检查其他方法的权限。
    """
    ret = Request(request=request._request,
                  parsers=request.parsers,
                  authenticators=request.authenticators,
                  negotiator=request.negotiator,
                  parser_context=request.parser_context)
    ret._data = request._data
    ret._files = request._files
    ret._full_data = request._full_data
    ret._content_type = request._content_type
    ret._stream = request._stream
    ret.method = method
    if hasattr(request, '_user'):
        ret._user = request._user
    if hasattr(request, '_auth'):
        ret._auth = request._auth
    if hasattr(request, '_authenticator'):
        ret._authenticator = request._authenticator
    if hasattr(request, 'accepted_renderer'):
        ret.accepted_renderer = request.accepted_renderer
    if hasattr(request, 'accepted_media_type'):
        ret.accepted_media_type = request.accepted_media_type
    if hasattr(request, 'version'):
        ret.version = request.version
    if hasattr(request, 'versioning_scheme'):
        ret.versioning_scheme = request.versioning_scheme
    return ret


class ForcedAuthentication(object):
    """
    如果测试客户端或请求工厂强制认证请求，则使用此认证类。
    """

    def __init__(self, force_user, force_token):
        self.force_user = force_user
        self.force_token = force_token

    def authenticate(self, request):
        return (self.force_user, self.force_token)


class Request(object):
    """
    包装允许增强标准的`HttpRequest`实例。

    Kwargs:
        - request(HttpRequest). 原始请求实例。
        - parsers_classes(list/tuple). 解析器用于解析请求内容。
        - authentication_classes(list/tuple). 用于验证请求用户的身份验证
    """

    def __init__(self, request, parsers=None, authenticators=None,
                 negotiator=None, parser_context=None):
        assert isinstance(request, HttpRequest), (
            'The `request` argument must be an instance of '
            '`django.http.HttpRequest`, not `{}.{}`.'
            .format(request.__class__.__module__, request.__class__.__name__)
        )

        self._request = request
        self.parsers = parsers or ()
        self.authenticators = authenticators or ()
        self.negotiator = negotiator or self._default_negotiator()
        self.parser_context = parser_context
        self._data = Empty
        self._files = Empty
        self._full_data = Empty
        self._content_type = Empty
        self._stream = Empty

        if self.parser_context is None:
            self.parser_context = {}
        self.parser_context['request'] = self
        self.parser_context['encoding'] = request.encoding or settings.DEFAULT_CHARSET

        force_user = getattr(request, '_force_auth_user', None)
        force_token = getattr(request, '_force_auth_token', None)
        if force_user is not None or force_token is not None:
            forced_auth = ForcedAuthentication(force_user, force_token)
            self.authenticators = (forced_auth,)

    def _default_negotiator(self):
        return api_settings.DEFAULT_CONTENT_NEGOTIATION_CLASS()

    @property
    def content_type(self):
        meta = self._request.META
        return meta.get('CONTENT_TYPE', meta.get('HTTP_CONTENT_TYPE', ''))

    @property
    def stream(self):
        """
        返回可用于流式传输请求内容的对象。
        """
        if not _hasattr(self, '_stream'):
            self._load_stream()
        return self._stream

    @property
    def query_params(self):
        """
        request.GET的语义上更正确的名称。
        """
        return self._request.GET

    @property
    def data(self):
        if not _hasattr(self, '_full_data'):
            self._load_data_and_files()
        return self._full_data

    @property
    def user(self):
        """
        返回与当前请求关联的用户，并通过提供给请求的认证类进行认证。
        """
        if not hasattr(self, '_user'):
            with wrap_attributeerrors():
                self._authenticate()
        return self._user

    @user.setter
    def user(self, value):
        """
        根据当前请求设置用户。 
        这对于保持与django.contrib.auth的兼容性是必要的，
        其中在登录和注销功能中设置了用户属性。

        请注意，我们还将用户设置为Django的基础`HttpRequest`实例，
        确保它可用于堆栈中的任何中间件。
        """
        self._user = value
        self._request.user = value

    @property
    def auth(self):
        """
        返回与请求关联的任何非用户身份验证信息，例如身份验证令牌。
        """
        if not hasattr(self, '_auth'):
            with wrap_attributeerrors():
                self._authenticate()
        return self._auth

    @auth.setter
    def auth(self, value):
        """
        设置与请求关联的任何非用户身份验证信息，例如身份验证令牌。
        """
        self._auth = value
        self._request.auth = value

    @property
    def successful_authenticator(self):
        """
        返回用于验证请求的身份验证实例类的实例或“None”。
        """
        if not hasattr(self, '_authenticator'):
            with wrap_attributeerrors():
                self._authenticate()
        return self._authenticator

    def _load_data_and_files(self):
        """
        将请求内容解析为`self.data`。
        """
        if not _hasattr(self, '_data'):
            self._data, self._files = self._parse()
            if self._files:
                self._full_data = self._data.copy()
                self._full_data.update(self._files)
            else:
                self._full_data = self._data

            # 将数据和文件复制到底层请求，以便可关闭的对象得到适当的处理。
            self._request._post = self.POST
            self._request._files = self.FILES

    def _load_stream(self):
        """
        以流的形式返回请求的内容正文。
        """
        meta = self._request.META
        try:
            content_length = int(
                meta.get('CONTENT_LENGTH', meta.get('HTTP_CONTENT_LENGTH', 0))
            )
        except (ValueError, TypeError):
            content_length = 0

        if content_length == 0:
            self._stream = None
        elif not self._request._read_started:
            self._stream = self._request
        else:
            self._stream = six.BytesIO(self.body)

    def _supports_form_parsing(self):
        """
        如果此请求支持解析表单数据，则返回True。
        """
        form_media = (
            'application/x-www-form-urlencoded',
            'multipart/form-data'
        )
        return any([parser.media_type in form_media for parser in self.parsers])

    def _parse(self):
        """
        解析请求内容，返回（data, files）两元组可能引发`UnsupportedMediaType`或`ParseError`异常。
        """
        media_type = self.content_type
        try:
            stream = self.stream
        except RawPostDataException:
            if not hasattr(self._request, '_post'):
                raise
            # 如果request.POST已经在中间件中被访问，
            # 并且method='POST'请求是通过'multipart/form-data''进行的，
            # 那么请求流已经用尽。
            if self._supports_form_parsing():
                return (self._request.POST, self._request.FILES)
            stream = None

        if stream is None or media_type is None:
            if media_type and is_form_media_type(media_type):
                empty_data = QueryDict('', encoding=self._request._encoding)
            else:
                empty_data = {}
            empty_files = MultiValueDict()
            return (empty_data, empty_files)

        parser = self.negotiator.select_parser(self, self.parsers)

        if not parser:
            raise exceptions.UnsupportedMediaType(media_type)

        try:
            parsed = parser.parse(stream, media_type, self.parser_context)
        except Exception:
            # 如果我们在解析过程中遇到异常，请填写空白数据并重新提升。
            # 确保在尝试呈现可浏览的渲染器响应时或在记录请求或类似内容时，我们不会简单地重复该错误。
            self._data = QueryDict('', encoding=self._request._encoding)
            self._files = MultiValueDict()
            self._full_data = self._data
            raise

        # 解析器类可能会返回原始数据或DataAndFiles对象。 根据需要解包结果。
        try:
            return (parsed.data, parsed.files)
        except AttributeError:
            empty_files = MultiValueDict()
            return (parsed, empty_files)

    def _authenticate(self):
        """
        尝试依次使用每个验证实例验证请求。
        """
        for authenticator in self.authenticators:
            try:
                user_auth_tuple = authenticator.authenticate(self)
            except exceptions.APIException:
                self._not_authenticated()
                raise

            if user_auth_tuple is not None:
                self._authenticator = authenticator
                self.user, self.auth = user_auth_tuple
                return

        self._not_authenticated()

    def _not_authenticated(self):
        """
        设置authenticator，user＆authtoken表示未经身份验证的请求。

        默认值为None，AnonymousUser＆None。
        """
        self._authenticator = None

        if api_settings.UNAUTHENTICATED_USER:
            self.user = api_settings.UNAUTHENTICATED_USER()
        else:
            self.user = None

        if api_settings.UNAUTHENTICATED_TOKEN:
            self.auth = api_settings.UNAUTHENTICATED_TOKEN()
        else:
            self.auth = None

    def __getattr__(self, attr):
        """
        如果一个属性在这个实例中不存在，那么我们也试图将它代理到底层的HttpRequest对象。
        """
        try:
            return getattr(self._request, attr)
        except AttributeError:
            return self.__getattribute__(attr)

    @property
    def DATA(self):
        raise NotImplementedError(
            '`request.DATA` has been deprecated in favor of `request.data` '
            'since version 3.0, and has been fully removed as of version 3.2.'
        )

    @property
    def POST(self):
        # 确保request.POST使用我们的请求解析。
        if not _hasattr(self, '_data'):
            self._load_data_and_files()
        if is_form_media_type(self.content_type):
            return self._data
        return QueryDict('', encoding=self._request._encoding)

    @property
    def FILES(self):
        # 向后兼容Django的request.FILES与其他两种情况不同，
        # 它们不是WSGIRequest类中的有效属性名称。
        if not _hasattr(self, '_files'):
            self._load_data_and_files()
        return self._files

    @property
    def QUERY_PARAMS(self):
        raise NotImplementedError(
            '`request.QUERY_PARAMS` has been deprecated in favor of `request.query_params` '
            'since version 3.0, and has been fully removed as of version 3.2.'
        )

    def force_plaintext_errors(self, value):
        # 黑客让我们的异常处理程序强制选择纯文本或html错误响应。
        self._request.is_ajax = lambda: value
