# -- coding: utf-8 --

# 请注意，我们导入为`DjangoRequestFactory`和`DjangoClient`，
# 以便让用户难以在无意识的情况下导入错误的东西。
from __future__ import unicode_literals

import io

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.handlers.wsgi import WSGIHandler
from django.test import testcases
from django.test.client import Client as DjangoClient
from django.test.client import RequestFactory as DjangoRequestFactory
from django.test.client import ClientHandler
from django.utils import six
from django.utils.encoding import force_bytes
from django.utils.http import urlencode

from rest_framework.compat import coreapi, requests
from rest_framework.settings import api_settings


def force_authenticate(request, user=None, token=None):
    request._force_auth_user = user
    request._force_auth_token = token


if requests is not None:
    class HeaderDict(requests.packages.urllib3._collections.HTTPHeaderDict):
        def get_all(self, key, default):
            return self.getheaders(key)

    class MockOriginalResponse(object):
        def __init__(self, headers):
            self.msg = HeaderDict(headers)
            self.closed = False

        def isclosed(self):
            return self.closed

        def close(self):
            self.closed = True

    class DjangoTestAdapter(requests.adapters.HTTPAdapter):
        """
        `request`的传输适配器，它通过Django WSGI应用程序发出请求，而不是通过网络发出实际的HTTP请求。
        """
        def __init__(self):
            self.app = WSGIHandler()
            self.factory = DjangoRequestFactory()

        def get_environ(self, request):
            """
            给定一个`requests.PreparedRequest`实例，返回一个WSGI environ字典。
            """
            method = request.method
            url = request.url
            kwargs = {}

            # 设置请求内容（如果存在）。
            if request.body is not None:
                if hasattr(request.body, 'read'):
                    kwargs['data'] = request.body.read()
                else:
                    kwargs['data'] = request.body
            if 'content-type' in request.headers:
                kwargs['content_type'] = request.headers['content-type']

            # 设置请求头。
            for key, value in request.headers.items():
                key = key.upper()
                if key in ('CONNECTION', 'CONTENT-LENGTH', 'CONTENT-TYPE'):
                    continue
                kwargs['HTTP_%s' % key.replace('-', '_')] = value

            return self.factory.generic(method, url, **kwargs).environ

        def send(self, request, *args, **kwargs):
            """
            向Django WSGI应用程序发出传出请求。
            """
            raw_kwargs = {}

            def start_response(wsgi_status, wsgi_headers):
                status, _, reason = wsgi_status.partition(' ')
                raw_kwargs['status'] = int(status)
                raw_kwargs['reason'] = reason
                raw_kwargs['headers'] = wsgi_headers
                raw_kwargs['version'] = 11
                raw_kwargs['preload_content'] = False
                raw_kwargs['original_response'] = MockOriginalResponse(wsgi_headers)

            # 通过WSGI发出请求。
            environ = self.get_environ(request)
            wsgi_response = self.app(environ, start_response)

            # 构建底层的urllib3.HTTPResponse
            raw_kwargs['body'] = io.BytesIO(b''.join(wsgi_response))
            raw = requests.packages.urllib3.HTTPResponse(**raw_kwargs)

            # 构建请求.响应
            return self.build_response(request, raw)

        def close(self):
            pass

    class RequestsClient(requests.Session):
        def __init__(self, *args, **kwargs):
            super(RequestsClient, self).__init__(*args, **kwargs)
            adapter = DjangoTestAdapter()
            self.mount('http://', adapter)
            self.mount('https://', adapter)

        def request(self, method, url, *args, **kwargs):
            if not url.startswith('http'):
                raise ValueError('Missing "http:" or "https:". Use a fully qualified URL, eg "http://testserver%s"' % url)
            return super(RequestsClient, self).request(method, url, *args, **kwargs)

else:
    def RequestsClient(*args, **kwargs):
        raise ImproperlyConfigured('必须安装requests才能使用RequestsClient。')


if coreapi is not None:
    class CoreAPIClient(coreapi.Client):
        def __init__(self, *args, **kwargs):
            self._session = RequestsClient()
            kwargs['transports'] = [coreapi.transports.HTTPTransport(session=self.session)]
            return super(CoreAPIClient, self).__init__(*args, **kwargs)

        @property
        def session(self):
            return self._session

else:
    def CoreAPIClient(*args, **kwargs):
        raise ImproperlyConfigured('coreapi must be installed in order to use CoreAPIClient.')


class APIRequestFactory(DjangoRequestFactory):
    renderer_classes_list = api_settings.TEST_REQUEST_RENDERER_CLASSES
    default_format = api_settings.TEST_REQUEST_DEFAULT_FORMAT

    def __init__(self, enforce_csrf_checks=False, **defaults):
        self.enforce_csrf_checks = enforce_csrf_checks
        self.renderer_classes = {}
        for cls in self.renderer_classes_list:
            self.renderer_classes[cls.format] = cls
        super(APIRequestFactory, self).__init__(**defaults)

    def _encode_data(self, data, format=None, content_type=None):
        """
        编码返回两个元组的数据 (bytes, content_type)
        """

        if data is None:
            return ('', content_type)

        assert format is None or content_type is None, (
            '您不能同时设置`format`和`content_type`。'
        )

        if content_type:
            # 内容类型明确指定，将数据视为原始字符串
            ret = force_bytes(data, settings.DEFAULT_CHARSET)

        else:
            format = format or self.default_format

            assert format in self.renderer_classes, (
                "Invalid format '{0}'. Available formats are {1}. "
                "Set TEST_REQUEST_RENDERER_CLASSES to enable "
                "extra request formats.".format(
                    format,
                    ', '.join(["'" + fmt + "'" for fmt in self.renderer_classes.keys()])
                )
            )

            # 使用format并将数据呈现为字符串
            renderer = self.renderer_classes[format]()
            ret = renderer.render(data)

            # 确定渲染器的内容类型标题
            content_type = "{0}; charset={1}".format(
                renderer.media_type, renderer.charset
            )

            # 如果需要，将文本强制为字节。
            if isinstance(ret, six.text_type):
                ret = bytes(ret.encode(renderer.charset))

        return ret, content_type

    def get(self, path, data=None, **extra):
        r = {
            'QUERY_STRING': urlencode(data or {}, doseq=True),
        }
        if not data and '?' in path:
            # 修复以支持您在url中拥有参数的旧行为。
            # 见＃1461。
            query_string = force_bytes(path.split('?')[1])
            if six.PY3:
                query_string = query_string.decode('iso-8859-1')
            r['QUERY_STRING'] = query_string
        r.update(extra)
        return self.generic('GET', path, **r)

    def post(self, path, data=None, format=None, content_type=None, **extra):
        data, content_type = self._encode_data(data, format, content_type)
        return self.generic('POST', path, data, content_type, **extra)

    def put(self, path, data=None, format=None, content_type=None, **extra):
        data, content_type = self._encode_data(data, format, content_type)
        return self.generic('PUT', path, data, content_type, **extra)

    def patch(self, path, data=None, format=None, content_type=None, **extra):
        data, content_type = self._encode_data(data, format, content_type)
        return self.generic('PATCH', path, data, content_type, **extra)

    def delete(self, path, data=None, format=None, content_type=None, **extra):
        data, content_type = self._encode_data(data, format, content_type)
        return self.generic('DELETE', path, data, content_type, **extra)

    def options(self, path, data=None, format=None, content_type=None, **extra):
        data, content_type = self._encode_data(data, format, content_type)
        return self.generic('OPTIONS', path, data, content_type, **extra)

    def generic(self, method, path, data='',
                content_type='application/octet-stream', secure=False, **extra):
        # 包括CONTENT_TYPE，无论数据是否为空。
        if content_type is not None:
            extra['CONTENT_TYPE'] = str(content_type)

        return super(APIRequestFactory, self).generic(
            method, path, data, content_type, secure, **extra)

    def request(self, **kwargs):
        request = super(APIRequestFactory, self).request(**kwargs)
        request._dont_enforce_csrf_checks = not self.enforce_csrf_checks
        return request


class ForceAuthClientHandler(ClientHandler):
    """
    ClientHandler的补丁版本，可对传出请求强制进行身份验证。
    """

    def __init__(self, *args, **kwargs):
        self._force_user = None
        self._force_token = None
        super(ForceAuthClientHandler, self).__init__(*args, **kwargs)

    def get_response(self, request):
        # 这是我们可以用来修补request对象的最简单的地方。
        force_authenticate(request, self._force_user, self._force_token)
        return super(ForceAuthClientHandler, self).get_response(request)


class APIClient(APIRequestFactory, DjangoClient):
    def __init__(self, enforce_csrf_checks=False, **defaults):
        super(APIClient, self).__init__(**defaults)
        self.handler = ForceAuthClientHandler(enforce_csrf_checks)
        self._credentials = {}

    def credentials(self, **kwargs):
        """
        设置每个发出的请求头。
        """
        self._credentials = kwargs

    def force_authenticate(self, user=None, token=None):
        """
        用给定的用户和/或令牌强制认证发出的请求。
        """
        self.handler._force_user = user
        self.handler._force_token = token
        if user is None:
            self.logout()  # 如果需要，清除任何可能的会话信息

    def request(self, **kwargs):
        # 确保将所有证书集添加到每个请求中。
        kwargs.update(self._credentials)
        return super(APIClient, self).request(**kwargs)

    def get(self, path, data=None, follow=False, **extra):
        response = super(APIClient, self).get(path, data=data, **extra)
        if follow:
            response = self._handle_redirects(response, **extra)
        return response

    def post(self, path, data=None, format=None, content_type=None,
             follow=False, **extra):
        response = super(APIClient, self).post(
            path, data=data, format=format, content_type=content_type, **extra)
        if follow:
            response = self._handle_redirects(response, **extra)
        return response

    def put(self, path, data=None, format=None, content_type=None,
            follow=False, **extra):
        response = super(APIClient, self).put(
            path, data=data, format=format, content_type=content_type, **extra)
        if follow:
            response = self._handle_redirects(response, **extra)
        return response

    def patch(self, path, data=None, format=None, content_type=None,
              follow=False, **extra):
        response = super(APIClient, self).patch(
            path, data=data, format=format, content_type=content_type, **extra)
        if follow:
            response = self._handle_redirects(response, **extra)
        return response

    def delete(self, path, data=None, format=None, content_type=None,
               follow=False, **extra):
        response = super(APIClient, self).delete(
            path, data=data, format=format, content_type=content_type, **extra)
        if follow:
            response = self._handle_redirects(response, **extra)
        return response

    def options(self, path, data=None, format=None, content_type=None,
                follow=False, **extra):
        response = super(APIClient, self).options(
            path, data=data, format=format, content_type=content_type, **extra)
        if follow:
            response = self._handle_redirects(response, **extra)
        return response

    def logout(self):
        self._credentials = {}

        # 同时清除所有的`force_authenticate`
        self.handler._force_user = None
        self.handler._force_token = None

        if self.session:
            super(APIClient, self).logout()


class APITransactionTestCase(testcases.TransactionTestCase):
    client_class = APIClient


class APITestCase(testcases.TestCase):
    client_class = APIClient


class APISimpleTestCase(testcases.SimpleTestCase):
    client_class = APIClient


class APILiveServerTestCase(testcases.LiveServerTestCase):
    client_class = APIClient
