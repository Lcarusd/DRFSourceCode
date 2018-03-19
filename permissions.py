"""
提供一组可插入的权限策略。
"""
from __future__ import unicode_literals

from django.http import Http404

from rest_framework import exceptions

SAFE_METHODS = ('GET', 'HEAD', 'OPTIONS')


class BasePermission(object):
    """
    所有权限类应从其继承的基类。
    """

    def has_permission(self, request, view):
        """
        如果授予权限，则返回“True”，否则返回False。
        """
        return True

    def has_object_permission(self, request, view, obj):
        """
        如果授予权限，则返回“True”，否则返回False。
        """
        return True


class AllowAny(BasePermission):
    """
    允许任何访问。
    这不是严格要求的，因为你可以使用一个空的permission_classes列表，
    但是它很有用，因为它使得意图更加明确。
    """

    def has_permission(self, request, view):
        return True


class IsAuthenticated(BasePermission):
    """
    只允许经过认证的用户访问。
    """

    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated


class IsAdminUser(BasePermission):
    """
    只允许管理员用户访问。
    """

    def has_permission(self, request, view):
        return request.user and request.user.is_staff


class IsAuthenticatedOrReadOnly(BasePermission):
    """
    该请求以用户身份进行身份验证，或者是只读请求。
    """

    def has_permission(self, request, view):
        return (
            request.method in SAFE_METHODS or
            request.user and
            request.user.is_authenticated
        )


class DjangoModelPermissions(BasePermission):
    """
    该请求使用`django.contrib.auth`权限进行身份验证。
    见: https://docs.djangoproject.com/en/dev/topics/auth/#permissions


    它确保用户通过身份验证，并且在模型上具有适当的“添加”/“更改”/“删除”权限。

    此权限只能应用于提供`.queryset`属性的视图类。
    """

    # 将方法映射到所需的权限代码。
    # 如果您还需要提供"view"权限，或者您想提供自定义权限代码，则覆盖此选项。
    perms_map = {
        'GET': [],
        'OPTIONS': [],
        'HEAD': [],
        'POST': ['%(app_label)s.add_%(model_name)s'],
        'PUT': ['%(app_label)s.change_%(model_name)s'],
        'PATCH': ['%(app_label)s.change_%(model_name)s'],
        'DELETE': ['%(app_label)s.delete_%(model_name)s'],
    }

    authenticated_users_only = True

    def get_required_permissions(self, method, model_cls):
        """
        给定一个模型和一个HTTP方法，返回用户需要拥有的权限代码列表。
        """
        kwargs = {
            'app_label': model_cls._meta.app_label,
            'model_name': model_cls._meta.model_name
        }

        if method not in self.perms_map:
            raise exceptions.MethodNotAllowed(method)

        return [perm % kwargs for perm in self.perms_map[method]]

    def _queryset(self, view):
        assert hasattr(view, 'get_queryset') \
            or getattr(view, 'queryset', None) is not None, (
            'Cannot apply {} on a view that does not set '
            '`.queryset` or have a `.get_queryset()` method.'
        ).format(self.__class__.__name__)

        if hasattr(view, 'get_queryset'):
            queryset = view.get_queryset()
            assert queryset is not None, (
                '{}.get_queryset() returned None'.format(view.__class__.__name__)
            )
            return queryset
        return view.queryset

    def has_permission(self, request, view):
        # 在使用DefaultRouter时，
        # 确保DjangoModelPermissions不应用于根视图的解决方法。
        if getattr(view, '_ignore_model_permissions', False):
            return True

        if not request.user or (
           not request.user.is_authenticated and self.authenticated_users_only):
            return False

        queryset = self._queryset(view)
        perms = self.get_required_permissions(request.method, queryset.model)

        return request.user.has_perms(perms)


class DjangoModelPermissionsOrAnonReadOnly(DjangoModelPermissions):
    """
    类似于DjangoModelPermissions，除了匿名用户被允许为只读访问。
    """
    authenticated_users_only = False


class DjangoObjectPermissions(DjangoModelPermissions):
    """
    该请求使用Django的对象级权限进行身份验证。
    它需要启用对象权限的后端，如Django Guardian。

    它确保用户通过身份验证，并使用.has_perms对该对象具有相应的“添加”/“更改”/“删除”权限。

    此权限只能应用于提供`.queryset`属性的视图类。
    """
    perms_map = {
        'GET': [],
        'OPTIONS': [],
        'HEAD': [],
        'POST': ['%(app_label)s.add_%(model_name)s'],
        'PUT': ['%(app_label)s.change_%(model_name)s'],
        'PATCH': ['%(app_label)s.change_%(model_name)s'],
        'DELETE': ['%(app_label)s.delete_%(model_name)s'],
    }

    def get_required_object_permissions(self, method, model_cls):
        kwargs = {
            'app_label': model_cls._meta.app_label,
            'model_name': model_cls._meta.model_name
        }

        if method not in self.perms_map:
            raise exceptions.MethodNotAllowed(method)

        return [perm % kwargs for perm in self.perms_map[method]]

    def has_object_permission(self, request, view, obj):
        # 身份验证检查已通过has_permission执行
        queryset = self._queryset(view)
        model_cls = queryset.model
        user = request.user

        perms = self.get_required_object_permissions(request.method, model_cls)

        if not user.has_perms(perms, obj):
            # 如果用户没有权限，我们需要确定他们是否具有读取权限以查看403，
            # 并且仅查看404响应。

            if request.method in SAFE_METHODS:
                # 读取权限已经检查并失败，无需再进行查找。
                raise Http404

            read_perms = self.get_required_object_permissions('GET', model_cls)
            if not user.has_perms(read_perms, obj):
                raise Http404

            # 已阅读权限。
            return False

        return True
