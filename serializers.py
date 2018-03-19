"""
Serializers和ModelSerializer类似于Forms和ModelForms。
与表单不同，它们不受限于处理HTML输出，并且形成编码输入。

REST框架中的序列化是一个两阶段过程：
1.序列化器在诸如模型实例之类的复杂类型和python原函数（primitives）之间编组。
2. Python原函数（primitives）与请求和响应内容之间的编组过程由解析器和渲染器处理。
"""
from __future__ import unicode_literals

import copy
import inspect
import traceback
from collections import Mapping, OrderedDict

from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.db.models import DurationField as ModelDurationField
from django.db.models.fields import Field as DjangoModelField
from django.db.models.fields import FieldDoesNotExist
from django.utils import six, timezone
from django.utils.functional import cached_property
from django.utils.translation import ugettext_lazy as _

from rest_framework.compat import postgres_fields, unicode_to_repr
from rest_framework.exceptions import ErrorDetail, ValidationError
from rest_framework.fields import get_error_detail, set_value
from rest_framework.settings import api_settings
from rest_framework.utils import html, model_meta, representation
from rest_framework.utils.field_mapping import (
    ClassLookupDict, get_field_kwargs, get_nested_relation_kwargs,
    get_relation_kwargs, get_url_kwargs
)
from rest_framework.utils.serializer_helpers import (
    BindingDict, BoundField, JSONBoundField, NestedBoundField, ReturnDict,
    ReturnList
)
from rest_framework.validators import (
    UniqueForDateValidator, UniqueForMonthValidator, UniqueForYearValidator,
    UniqueTogetherValidator
)

# 注意：我们执行以下操作，以便框架的用户可以使用此样式：
#
#     example_field = serializers.CharField(...)
#
# 这有助于更加明确地保持模型字段，表单字段和序列化程序字段之间的分离。
from rest_framework.fields import (  # NOQA # isort:skip
    BooleanField, CharField, ChoiceField, DateField, DateTimeField, DecimalField,
    DictField, DurationField, EmailField, Field, FileField, FilePathField, FloatField,
    HiddenField, IPAddressField, ImageField, IntegerField, JSONField, ListField,
    ModelField, MultipleChoiceField, NullBooleanField, ReadOnlyField, RegexField,
    SerializerMethodField, SlugField, TimeField, URLField, UUIDField,
)
from rest_framework.relations import (  # NOQA # isort:skip
    HyperlinkedIdentityField, HyperlinkedRelatedField, ManyRelatedField,
    PrimaryKeyRelatedField, RelatedField, SlugRelatedField, StringRelatedField,
)

# 非字段导入，公开的API
from rest_framework.fields import (  # NOQA # isort:skip
    CreateOnlyDefault, CurrentUserDefault, SkipField, empty
)
from rest_framework.relations import Hyperlink, PKOnlyObject  # NOQA # isort:skip

# 我们假设'验证器'是为子序列化器而不是父序列化器。
LIST_SERIALIZER_KWARGS = (
    'read_only', 'write_only', 'required', 'default', 'initial', 'source',
    'label', 'help_text', 'style', 'error_messages', 'allow_empty',
    'instance', 'data', 'partial', 'context', 'allow_null'
)

ALL_FIELDS = '__all__'


# 序列化基类
# --------------

class BaseSerializer(Field):
    """
    BaseSerializer类提供了一个可用于编写自定义序列化器实现的最小类。

    请注意，我们强烈限制序列化程序中可能使用的操作/属性的顺序，以强制正确使用。

    特别是，如果通过了`data =`参数，那么：
    .is_valid() - 可用
    .initial_data - 可用
    .validated_data - 只有在调用`is_valid（）`后才可用
    .errors - 只有在调用`is_valid（）`后才可用
    .data - 只有在调用`is_valid（）`后才可用

    如果一个`data =`参数没有通过，那么：
    .is_valid() - 不可用
    .initial_data - 不可用
    .validated_data - 不可用
    .errors - 不可用
    .data - 可用
    """

    def __init__(self, instance=None, data=empty, **kwargs):
        self.instance = instance
        if data is not empty:
            self.initial_data = data
        self.partial = kwargs.pop('partial', False)
        self._context = kwargs.pop('context', {})
        kwargs.pop('many', None)
        super(BaseSerializer, self).__init__(**kwargs)

    def __new__(cls, *args, **kwargs):
        # 我们重写了这个方法，以便在设置'many = True'时自动创建`ListSerializer`类。
        if kwargs.pop('many', False):
            return cls.many_init(*args, **kwargs)
        return super(BaseSerializer, cls).__new__(cls, *args, **kwargs)

    @classmethod
    def many_init(cls, *args, **kwargs):
        """
        当使用`many = True`时，此方法实现`ListSerializer`父类的创建。
        如果您需要控制将哪些关键字参数传递给父项，
        并将哪些关键字参数传递给子项，
        则可以对其进行自定义。

        请注意，为了试图涵盖一般情况，我们在将大多数参数传递给父类和子类时过于谨慎。
        如果你重写这个方法，你可能会想要更简单的东西，例如：

        @classmethod
        def many_init(cls, *args, **kwargs):
            kwargs['child'] = cls()
            return CustomListSerializer(*args, **kwargs)
        """
        allow_empty = kwargs.pop('allow_empty', None)
        child_serializer = cls(*args, **kwargs)
        list_kwargs = {
            'child': child_serializer,
        }
        if allow_empty is not None:
            list_kwargs['allow_empty'] = allow_empty
        list_kwargs.update({
            key: value for key, value in kwargs.items()
            if key in LIST_SERIALIZER_KWARGS
        })
        meta = getattr(cls, 'Meta', None)
        list_serializer_class = getattr(meta, 'list_serializer_class', ListSerializer)
        return list_serializer_class(*args, **list_kwargs)

    def to_internal_value(self, data):
        raise NotImplementedError('`to_internal_value()` 必须实现.')

    def to_representation(self, instance):
        raise NotImplementedError('`to_representation()` 必须实现.')

    def update(self, instance, validated_data):
        raise NotImplementedError('`update()` 必须实现.')

    def create(self, validated_data):
        raise NotImplementedError('`create()` 必须实现.')

    def save(self, **kwargs):
        assert not hasattr(self, 'save_object'), (
            'Serializer `%s.%s` has old-style version 2 `.save_object()` '
            'that is no longer compatible with REST framework 3. '
            'Use the new-style `.create()` and `.update()` methods instead.' %
            (self.__class__.__module__, self.__class__.__name__)
        )

        assert hasattr(self, '_errors'), (
            '在调用`.save（）`之前，您必须调用`.is_valid（）`。'
        )

        assert not self.errors, (
            '您无法在无效数据的序列化器上调用`.save（）`。'
        )

        # 防止错误使用`serializer.save（commit = False）`
        assert 'commit' not in kwargs, (
            "'commit' is not a valid keyword argument to the 'save()' method. "
            "If you need to access data before committing to the database then "
            "inspect 'serializer.validated_data' instead. "
            "You can also pass additional keyword arguments to 'save()' if you "
            "need to set extra attributes on the saved model instance. "
            "For example: 'serializer.save(owner=request.user)'.'"
        )

        assert not hasattr(self, '_data'), (
            "You cannot call `.save()` after accessing `serializer.data`."
            "If you need to access data before committing to the database then "
            "inspect 'serializer.validated_data' instead. "
        )

        validated_data = dict(
            list(self.validated_data.items()) +
            list(kwargs.items())
        )

        if self.instance is not None:
            self.instance = self.update(self.instance, validated_data)
            assert self.instance is not None, (
                '`update()` did not return an object instance.'
            )
        else:
            self.instance = self.create(validated_data)
            assert self.instance is not None, (
                '`create()` did not return an object instance.'
            )

        return self.instance

    def is_valid(self, raise_exception=False):
        assert not hasattr(self, 'restore_object'), (
            'Serializer `%s.%s` has old-style version 2 `.restore_object()` '
            'that is no longer compatible with REST framework 3. '
            'Use the new-style `.create()` and `.update()` methods instead.' %
            (self.__class__.__module__, self.__class__.__name__)
        )

        assert hasattr(self, 'initial_data'), (
            'Cannot call `.is_valid()` as no `data=` keyword argument was '
            'passed when instantiating the serializer instance.'
        )

        if not hasattr(self, '_validated_data'):
            try:
                self._validated_data = self.run_validation(self.initial_data)
            except ValidationError as exc:
                self._validated_data = {}
                self._errors = exc.detail
            else:
                self._errors = {}

        if self._errors and raise_exception:
            raise ValidationError(self.errors)

        return not bool(self._errors)

    @property
    def data(self):
        if hasattr(self, 'initial_data') and not hasattr(self, '_validated_data'):
            msg = (
                'When a serializer is passed a `data` keyword argument you '
                'must call `.is_valid()` before attempting to access the '
                'serialized `.data` representation.\n'
                'You should either call `.is_valid()` first, '
                'or access `.initial_data` instead.'
            )
            raise AssertionError(msg)

        if not hasattr(self, '_data'):
            if self.instance is not None and not getattr(self, '_errors', None):
                self._data = self.to_representation(self.instance)
            elif hasattr(self, '_validated_data') and not getattr(self, '_errors', None):
                self._data = self.to_representation(self.validated_data)
            else:
                self._data = self.get_initial()
        return self._data

    @property
    def errors(self):
        if not hasattr(self, '_errors'):
            msg = 'You must call `.is_valid()` before accessing `.errors`.'
            raise AssertionError(msg)
        return self._errors

    @property
    def validated_data(self):
        if not hasattr(self, '_validated_data'):
            msg = 'You must call `.is_valid()` before accessing `.validated_data`.'
            raise AssertionError(msg)
        return self._validated_data


# Serializer & ListSerializer classes
# -----------------------------------

class SerializerMetaclass(type):
    """
    这个元类在类上设置了一个名为`_declared_fields`的字典。

    任何包含在类或其任何超类上的属性的Field的实例都将包含在`_declared_fields`字典中。
    """

    @classmethod
    def _get_declared_fields(cls, bases, attrs):
        fields = [(field_name, attrs.pop(field_name))
                  for field_name, obj in list(attrs.items())
                  if isinstance(obj, Field)]
        fields.sort(key=lambda x: x[1]._creation_counter)

        # 如果这个类继承另一个序列化器，请添加序列器的字段。
        # 请注意，我们在相反的位置循环遍历bases。
        # 这是必要的，以保持字段的正确顺序。
        for base in reversed(bases):
            if hasattr(base, '_declared_fields'):
                fields = [
                    (field_name, obj) for field_name, obj
                    in base._declared_fields.items()
                    if field_name not in attrs
                ] + fields

        return OrderedDict(fields)

    def __new__(cls, name, bases, attrs):
        attrs['_declared_fields'] = cls._get_declared_fields(bases, attrs)
        return super(SerializerMetaclass, cls).__new__(cls, name, bases, attrs)


def as_serializer_error(exc):
    assert isinstance(exc, (ValidationError, DjangoValidationError))

    if isinstance(exc, DjangoValidationError):
        detail = get_error_detail(exc)
    else:
        detail = exc.detail

    if isinstance(detail, Mapping):
        # 如果错误可能是字典，我们使用标准{key: 值列表}。
        # 这里我们确保所有的值都是错误列表。
        return {
            key: value if isinstance(value, (list, Mapping)) else [value]
            for key, value in detail.items()
        }
    elif isinstance(detail, list):
        # 作为列表引发的错误是非字段错误。
        return {
            api_settings.NON_FIELD_ERRORS_KEY: detail
        }
    # 作为字符串引发的错误是非字段错误。
    return {
        api_settings.NON_FIELD_ERRORS_KEY: [detail]
    }


@six.add_metaclass(SerializerMetaclass)
class Serializer(BaseSerializer):
    default_error_messages = {
        'invalid': _('Invalid data. Expected a dictionary, but got {datatype}.')
    }

    @property
    def fields(self):
        """
        {field_name：field_instance}的字典。
        """
        # 惰性加载`fields`.
        # 我们这样做是为了确保我们没有导入使用ModelSerializers作为字段的模块的问题，
        # 即使Django的应用程序加载阶段尚未运行。
        if not hasattr(self, '_fields'):
            self._fields = BindingDict(self)
            for key, value in self.get_fields().items():
                self._fields[key] = value
        return self._fields

    @cached_property
    def _writable_fields(self):
        return [
            field for field in self.fields.values()
            if (not field.read_only) or (field.default is not empty)
        ]

    @cached_property
    def _readable_fields(self):
        return [
            field for field in self.fields.values()
            if not field.write_only
        ]

    def get_fields(self):
        """
        Returns a dictionary of {field_name: field_instance}.
        """
        # Every new serializer is created with a clone of the field instances.
        # This allows users to dynamically modify the fields on a serializer
        # instance without affecting every other serializer instance.
        return copy.deepcopy(self._declared_fields)

    def get_validators(self):
        """
        Returns a list of validator callables.
        """
        # Used by the lazily-evaluated `validators` property.
        meta = getattr(self, 'Meta', None)
        validators = getattr(meta, 'validators', None)
        return validators[:] if validators else []

    def get_initial(self):
        if hasattr(self, 'initial_data'):
            # initial_data may not be a valid type
            if not isinstance(self.initial_data, Mapping):
                return OrderedDict()

            return OrderedDict([
                (field_name, field.get_value(self.initial_data))
                for field_name, field in self.fields.items()
                if (field.get_value(self.initial_data) is not empty) and
                not field.read_only
            ])

        return OrderedDict([
            (field.field_name, field.get_initial())
            for field in self.fields.values()
            if not field.read_only
        ])

    def get_value(self, dictionary):
        # We override the default field access in order to support
        # nested HTML forms.
        if html.is_html_input(dictionary):
            return html.parse_html_dict(dictionary, prefix=self.field_name) or empty
        return dictionary.get(self.field_name, empty)

    def run_validation(self, data=empty):
        """
        We override the default `run_validation`, because the validation
        performed by validators and the `.validate()` method should
        be coerced into an error dictionary with a 'non_fields_error' key.
        """
        (is_empty_value, data) = self.validate_empty_values(data)
        if is_empty_value:
            return data

        value = self.to_internal_value(data)
        try:
            self.run_validators(value)
            value = self.validate(value)
            assert value is not None, '.validate() should return the validated data'
        except (ValidationError, DjangoValidationError) as exc:
            raise ValidationError(detail=as_serializer_error(exc))

        return value

    def to_internal_value(self, data):
        """
        Dict of native values <- Dict of primitive datatypes.
        """
        if not isinstance(data, Mapping):
            message = self.error_messages['invalid'].format(
                datatype=type(data).__name__
            )
            raise ValidationError({
                api_settings.NON_FIELD_ERRORS_KEY: [message]
            }, code='invalid')

        ret = OrderedDict()
        errors = OrderedDict()
        fields = self._writable_fields

        for field in fields:
            validate_method = getattr(self, 'validate_' + field.field_name, None)
            primitive_value = field.get_value(data)
            try:
                validated_value = field.run_validation(primitive_value)
                if validate_method is not None:
                    validated_value = validate_method(validated_value)
            except ValidationError as exc:
                errors[field.field_name] = exc.detail
            except DjangoValidationError as exc:
                errors[field.field_name] = get_error_detail(exc)
            except SkipField:
                pass
            else:
                set_value(ret, field.source_attrs, validated_value)

        if errors:
            raise ValidationError(errors)

        return ret

    def to_representation(self, instance):
        """
        Object instance -> Dict of primitive datatypes.
        """
        ret = OrderedDict()
        fields = self._readable_fields

        for field in fields:
            try:
                attribute = field.get_attribute(instance)
            except SkipField:
                continue

            # We skip `to_representation` for `None` values so that fields do
            # not have to explicitly deal with that case.
            #
            # For related fields with `use_pk_only_optimization` we need to
            # resolve the pk value.
            check_for_none = attribute.pk if isinstance(attribute, PKOnlyObject) else attribute
            if check_for_none is None:
                ret[field.field_name] = None
            else:
                ret[field.field_name] = field.to_representation(attribute)

        return ret

    def validate(self, attrs):
        return attrs

    def __repr__(self):
        return unicode_to_repr(representation.serializer_repr(self, indent=1))

    # The following are used for accessing `BoundField` instances on the
    # serializer, for the purposes of presenting a form-like API onto the
    # field values and field errors.

    def __iter__(self):
        for field in self.fields.values():
            yield self[field.field_name]

    def __getitem__(self, key):
        field = self.fields[key]
        value = self.data.get(key)
        error = self.errors.get(key) if hasattr(self, '_errors') else None
        if isinstance(field, Serializer):
            return NestedBoundField(field, value, error)
        if isinstance(field, JSONField):
            return JSONBoundField(field, value, error)
        return BoundField(field, value, error)

    # Include a backlink to the serializer class on return objects.
    # Allows renderers such as HTMLFormRenderer to get the full field info.

    @property
    def data(self):
        ret = super(Serializer, self).data
        return ReturnDict(ret, serializer=self)

    @property
    def errors(self):
        ret = super(Serializer, self).errors
        if isinstance(ret, list) and len(ret) == 1 and getattr(ret[0], 'code', None) == 'null':
            # Edge case. Provide a more descriptive error than
            # "this field may not be null", when no data is passed.
            detail = ErrorDetail('No data provided', code='null')
            ret = {api_settings.NON_FIELD_ERRORS_KEY: [detail]}
        return ReturnDict(ret, serializer=self)


# There's some replication of `ListField` here,
# but that's probably better than obfuscating the call hierarchy.

class ListSerializer(BaseSerializer):
    child = None
    many = True

    default_error_messages = {
        'not_a_list': _('Expected a list of items but got type "{input_type}".'),
        'empty': _('This list may not be empty.')
    }

    def __init__(self, *args, **kwargs):
        self.child = kwargs.pop('child', copy.deepcopy(self.child))
        self.allow_empty = kwargs.pop('allow_empty', True)
        assert self.child is not None, '`child` is a required argument.'
        assert not inspect.isclass(self.child), '`child` has not been instantiated.'
        super(ListSerializer, self).__init__(*args, **kwargs)
        self.child.bind(field_name='', parent=self)

    def bind(self, field_name, parent):
        super(ListSerializer, self).bind(field_name, parent)
        self.partial = self.parent.partial

    def get_initial(self):
        if hasattr(self, 'initial_data'):
            return self.to_representation(self.initial_data)
        return []

    def get_value(self, dictionary):
        """
        Given the input dictionary, return the field value.
        """
        # We override the default field access in order to support
        # lists in HTML forms.
        if html.is_html_input(dictionary):
            return html.parse_html_list(dictionary, prefix=self.field_name)
        return dictionary.get(self.field_name, empty)

    def run_validation(self, data=empty):
        """
        We override the default `run_validation`, because the validation
        performed by validators and the `.validate()` method should
        be coerced into an error dictionary with a 'non_fields_error' key.
        """
        (is_empty_value, data) = self.validate_empty_values(data)
        if is_empty_value:
            return data

        value = self.to_internal_value(data)
        try:
            self.run_validators(value)
            value = self.validate(value)
            assert value is not None, '.validate() should return the validated data'
        except (ValidationError, DjangoValidationError) as exc:
            raise ValidationError(detail=as_serializer_error(exc))

        return value

    def to_internal_value(self, data):
        """
        List of dicts of native values <- List of dicts of primitive datatypes.
        """
        if html.is_html_input(data):
            data = html.parse_html_list(data)

        if not isinstance(data, list):
            message = self.error_messages['not_a_list'].format(
                input_type=type(data).__name__
            )
            raise ValidationError({
                api_settings.NON_FIELD_ERRORS_KEY: [message]
            }, code='not_a_list')

        if not self.allow_empty and len(data) == 0:
            if self.parent and self.partial:
                raise SkipField()

            message = self.error_messages['empty']
            raise ValidationError({
                api_settings.NON_FIELD_ERRORS_KEY: [message]
            }, code='empty')

        ret = []
        errors = []

        for item in data:
            try:
                validated = self.child.run_validation(item)
            except ValidationError as exc:
                errors.append(exc.detail)
            else:
                ret.append(validated)
                errors.append({})

        if any(errors):
            raise ValidationError(errors)

        return ret

    def to_representation(self, data):
        """
        List of object instances -> List of dicts of primitive datatypes.
        """
        # Dealing with nested relationships, data can be a Manager,
        # so, first get a queryset from the Manager if needed
        iterable = data.all() if isinstance(data, models.Manager) else data

        return [
            self.child.to_representation(item) for item in iterable
        ]

    def validate(self, attrs):
        return attrs

    def update(self, instance, validated_data):
        raise NotImplementedError(
            "Serializers with many=True do not support multiple update by "
            "default, only multiple create. For updates it is unclear how to "
            "deal with insertions and deletions. If you need to support "
            "multiple update, use a `ListSerializer` class and override "
            "`.update()` so you can specify the behavior exactly."
        )

    def create(self, validated_data):
        return [
            self.child.create(attrs) for attrs in validated_data
        ]

    def save(self, **kwargs):
        """
        Save and return a list of object instances.
        """
        # Guard against incorrect use of `serializer.save(commit=False)`
        assert 'commit' not in kwargs, (
            "'commit' is not a valid keyword argument to the 'save()' method. "
            "If you need to access data before committing to the database then "
            "inspect 'serializer.validated_data' instead. "
            "You can also pass additional keyword arguments to 'save()' if you "
            "need to set extra attributes on the saved model instance. "
            "For example: 'serializer.save(owner=request.user)'.'"
        )

        validated_data = [
            dict(list(attrs.items()) + list(kwargs.items()))
            for attrs in self.validated_data
        ]

        if self.instance is not None:
            self.instance = self.update(self.instance, validated_data)
            assert self.instance is not None, (
                '`update()` did not return an object instance.'
            )
        else:
            self.instance = self.create(validated_data)
            assert self.instance is not None, (
                '`create()` did not return an object instance.'
            )

        return self.instance

    def is_valid(self, raise_exception=False):
        # This implementation is the same as the default,
        # except that we use lists, rather than dicts, as the empty case.
        assert hasattr(self, 'initial_data'), (
            'Cannot call `.is_valid()` as no `data=` keyword argument was '
            'passed when instantiating the serializer instance.'
        )

        if not hasattr(self, '_validated_data'):
            try:
                self._validated_data = self.run_validation(self.initial_data)
            except ValidationError as exc:
                self._validated_data = []
                self._errors = exc.detail
            else:
                self._errors = []

        if self._errors and raise_exception:
            raise ValidationError(self.errors)

        return not bool(self._errors)

    def __repr__(self):
        return unicode_to_repr(representation.list_repr(self, indent=1))

    # 在返回对象中包含反向链接器类的反向链接。
    # 允许HTMLFormRenderer等渲染器获取完整的字段信息。

    @property
    def data(self):
        ret = super(ListSerializer, self).data
        return ReturnList(ret, serializer=self)

    @property
    def errors(self):
        ret = super(ListSerializer, self).errors
        if isinstance(ret, list) and len(ret) == 1 and getattr(ret[0], 'code', None) == 'null':
            # Edge case. Provide a more descriptive error than
            # "this field may not be null", when no data is passed.
            detail = ErrorDetail('No data provided', code='null')
            ret = {api_settings.NON_FIELD_ERRORS_KEY: [detail]}
        if isinstance(ret, dict):
            return ReturnDict(ret, serializer=self)
        return ReturnList(ret, serializer=self)


# ModelSerializer & HyperlinkedModelSerializer
# --------------------------------------------

def raise_errors_on_nested_writes(method_name, serializer, validated_data):
    """
    当用户尝试传递可写入的嵌套数据时给出明确的错误。

    如果我们没有明确地做到这一点，那么在串行器上调用`.save（）`时会得到一个不太有用的错误。

    我们不会自动支持这些类型的嵌套写入，因为定义默认行为的含义过多。

    例如。 假设我们有一个带有嵌套配置文件的UserSerializer。 应该怎样
    我们处理更新的情况，“配置文件”关系所处的位置不存在？ 以下任何一种可能都是有效的：

     *引发应用程序错误。
     *默默忽略更新的嵌套部分。
     *自动创建一个配置文件实例。

    确保我们没有可写的嵌套字段。 例如：
    """

    # Ensure we don't have a writable nested field. For example:
    #
    # class UserSerializer(ModelSerializer):
    #     ...
    #     profile = ProfileSerializer()
    assert not any(
        isinstance(field, BaseSerializer) and
        (field.source in validated_data) and
        isinstance(validated_data[field.source], (list, dict))
        for field in serializer._writable_fields
    ), (
        'The `.{method_name}()` method does not support writable nested '
        'fields by default.\nWrite an explicit `.{method_name}()` method for '
        'serializer `{module}.{class_name}`, or set `read_only=True` on '
        'nested serializer fields.'.format(
            method_name=method_name,
            module=serializer.__class__.__module__,
            class_name=serializer.__class__.__name__
        )
    )

    # 确保我们没有可写的点源字段。 例如：
    #
    # class UserSerializer(ModelSerializer):
    #     ...
    #     address = serializer.CharField('profile.address')
    assert not any(
        '.' in field.source and
        (key in validated_data) and
        isinstance(validated_data[key], (list, dict))
        for key, field in serializer.fields.items()
    ), (
        'The `.{method_name}()` method does not support writable dotted-source '
        'fields by default.\nWrite an explicit `.{method_name}()` method for '
        'serializer `{module}.{class_name}`, or set `read_only=True` on '
        'dotted-source serializer fields.'.format(
            method_name=method_name,
            module=serializer.__class__.__module__,
            class_name=serializer.__class__.__name__
        )
    )


class ModelSerializer(Serializer):
    """
    一个`ModelSerializer`只是一个常规的`Serializer`，除了：

    *一组默认字段会自动填充。
    *一组默认验证器会自动填充。
    *提供了默认的`.create（）`和`.update（）`实现。

    基于模型字段自动确定一组序列化程序字段的过程相当复杂，但您几乎可以肯定不需要深入实施。

    如果`ModelSerializer`类没有生成你需要的字段集，你应该在序列化类上明确声明额外/不同的字段，
    或者简单地使用`Serializer`类。
    """
    serializer_field_mapping = {
        models.AutoField: IntegerField,
        models.BigIntegerField: IntegerField,
        models.BooleanField: BooleanField,
        models.CharField: CharField,
        models.CommaSeparatedIntegerField: CharField,
        models.DateField: DateField,
        models.DateTimeField: DateTimeField,
        models.DecimalField: DecimalField,
        models.EmailField: EmailField,
        models.Field: ModelField,
        models.FileField: FileField,
        models.FloatField: FloatField,
        models.ImageField: ImageField,
        models.IntegerField: IntegerField,
        models.NullBooleanField: NullBooleanField,
        models.PositiveIntegerField: IntegerField,
        models.PositiveSmallIntegerField: IntegerField,
        models.SlugField: SlugField,
        models.SmallIntegerField: IntegerField,
        models.TextField: CharField,
        models.TimeField: TimeField,
        models.URLField: URLField,
        models.GenericIPAddressField: IPAddressField,
        models.FilePathField: FilePathField,
    }
    if ModelDurationField is not None:
        serializer_field_mapping[ModelDurationField] = DurationField
    serializer_related_field = PrimaryKeyRelatedField
    serializer_related_to_field = SlugRelatedField
    serializer_url_field = HyperlinkedIdentityField
    serializer_choice_field = ChoiceField

    # 超链接标识字段的字段名称。 默认为'url'。
    # 您可以使用API设置对其进行修改。
    #
    # 请注意，如果您需要在每个序列化程序的基础上进行修改，
    # 则还需要确保更新任何通用视图上的create方法，
    # 以正确处理“HTTP 201 Created”响应的“位置”响应标头。
    url_field_name = None

    # 默认的"create"和"update"行为...
    def create(self, validated_data):
        """
        我们对此进行了一些额外的检查，以便在出现问题时提供描述性消息，但这种方法本质上只是：

            return ExampleModel.objects.create(**validated_data)

        如果实例中存在多个到多个字段，那么在实例化模型之前不能设置它们，在这种情况下，实现如下所示：

            example_relationship = validated_data.pop('example_relationship')
            instance = ExampleModel.objects.create(**validated_data)
            instance.example_relationship = example_relationship
            return instance

        如果实例中存在多个到多个字段，那么在实例化模型之前不能设置它们，在这种情况下，实现如下所示：
        """
        raise_errors_on_nested_writes('create', self, validated_data)

        ModelClass = self.Meta.model

        # 从validated_data中删除多对多关系。
        # 它们不是默认`.create（）`方法的有效参数，因为它们要求实例已保存。
        info = model_meta.get_field_info(ModelClass)
        many_to_many = {}
        for field_name, relation_info in info.relations.items():
            if relation_info.to_many and (field_name in validated_data):
                many_to_many[field_name] = validated_data.pop(field_name)

        try:
            instance = ModelClass.objects.create(**validated_data)
        except TypeError:
            tb = traceback.format_exc()
            msg = (
                'Got a `TypeError` when calling `%s.objects.create()`. '
                'This may be because you have a writable field on the '
                'serializer class that is not a valid argument to '
                '`%s.objects.create()`. You may need to make the field '
                'read-only, or override the %s.create() method to handle '
                'this correctly.\nOriginal exception was:\n %s' %
                (
                    ModelClass.__name__,
                    ModelClass.__name__,
                    self.__class__.__name__,
                    tb
                )
            )
            raise TypeError(msg)

        # 创建实例后保存多对多关系。
        if many_to_many:
            for field_name, value in many_to_many.items():
                field = getattr(instance, field_name)
                field.set(value)

        return instance

    def update(self, instance, validated_data):
        raise_errors_on_nested_writes('update', self, validated_data)
        info = model_meta.get_field_info(instance)

        # 只需在实例上设置每个属性，然后保存它。
        # 请注意，与`.create（）`不同，我们不需要将多对多关系视为一种特殊情况。
        # 在更新期间，我们已经有一个与关联关系的实例pk。
        for attr, value in validated_data.items():
            if attr in info.relations and info.relations[attr].to_many:
                field = getattr(instance, attr)
                field.set(value)
            else:
                setattr(instance, attr, value)
        instance.save()

        return instance

    # 确定要应用的字段...

    def get_fields(self):
        """
        返回字段名称的字典 - > 实例化序列化程序时应该用于`self.fields`的字段实例。
        """
        if self.url_field_name is None:
            self.url_field_name = api_settings.URL_FIELD_NAME

        assert hasattr(self, 'Meta'), (
            'Class {serializer_class} missing "Meta" attribute'.format(
                serializer_class=self.__class__.__name__
            )
        )
        assert hasattr(self.Meta, 'model'), (
            'Class {serializer_class} missing "Meta.model" attribute'.format(
                serializer_class=self.__class__.__name__
            )
        )
        if model_meta.is_abstract_model(self.Meta.model):
            raise ValueError(
                'Cannot use ModelSerializer with Abstract Models.'
            )

        declared_fields = copy.deepcopy(self._declared_fields)
        model = getattr(self.Meta, 'model')
        depth = getattr(self.Meta, 'depth', 0)

        if depth is not None:
            assert depth >= 0, "'depth' may not be negative."
            assert depth <= 10, "'depth' may not be greater than 10."

        # 检索相关模型类上的字段和关系的元数据。
        info = model_meta.get_field_info(model)
        field_names = self.get_field_names(declared_fields, info)

        # 确定应包含的任何额外字段参数和隐藏字段
        extra_kwargs = self.get_extra_kwargs()
        extra_kwargs, hidden_fields = self.get_uniqueness_extra_kwargs(
            field_names, declared_fields, extra_kwargs
        )

        # 确定应该包含在序列化程序中的字段。
        fields = OrderedDict()

        for field_name in field_names:
            # 如果该字段在该类上显式声明，则使用该字段。
            if field_name in declared_fields:
                fields[field_name] = declared_fields[field_name]
                continue

            extra_field_kwargs = extra_kwargs.get(field_name, {})
            source = extra_field_kwargs.get('source', '*')
            if source == '*':
                source = field_name

            # 确定序列化程序字段类和关键字参数。
            field_class, field_kwargs = self.build_field(
                source, info, model, depth
            )

            # 包含`Meta.extra_kwargs`中定义的任何kwargs
            field_kwargs = self.include_extra_kwargs(
                field_kwargs, extra_field_kwargs
            )

            # 创建序列化程序字段。
            fields[field_name] = field_class(**field_kwargs)

        # 添加任何隐藏的字段。
        fields.update(hidden_fields)

        return fields

    # 确定字段名称集以包含...的方法

    def get_field_names(self, declared_fields, info):
        """
        返回实例化此序列化程序类时应创建的所有字段名称的列表。
        这是基于默认的一组字段，
        但如果已经指定了它们，也会考虑“Meta.fields”或“Meta.exclude”选项。
        """
        fields = getattr(self.Meta, 'fields', None)
        exclude = getattr(self.Meta, 'exclude', None)

        if fields and fields != ALL_FIELDS and not isinstance(fields, (list, tuple)):
            raise TypeError(
                'The `fields` option must be a list or tuple or "__all__". '
                'Got %s.' % type(fields).__name__
            )

        if exclude and not isinstance(exclude, (list, tuple)):
            raise TypeError(
                'The `exclude` option must be a list or tuple. Got %s.' %
                type(exclude).__name__
            )

        assert not (fields and exclude), (
            "Cannot set both 'fields' and 'exclude' options on "
            "serializer {serializer_class}.".format(
                serializer_class=self.__class__.__name__
            )
        )

        assert not (fields is None and exclude is None), (
            "Creating a ModelSerializer without either the 'fields' attribute "
            "or the 'exclude' attribute has been deprecated since 3.3.0, "
            "and is now disallowed. Add an explicit fields = '__all__' to the "
            "{serializer_class} serializer.".format(
                serializer_class=self.__class__.__name__
            ),
        )

        if fields == ALL_FIELDS:
            fields = None

        if fields is not None:
            # 确保所有声明的字段也已包含在 `Meta.fields` 选项中。

            # 不要求任何声明为父类的字段，以便允许序列化子类只包含字段子集。
            required_field_names = set(declared_fields)
            for cls in self.__class__.__bases__:
                required_field_names -= set(getattr(cls, '_declared_fields', []))

            for field_name in required_field_names:
                assert field_name in fields, (
                    "The field '{field_name}' was declared on serializer "
                    "{serializer_class}, but has not been included in the "
                    "'fields' option.".format(
                        field_name=field_name,
                        serializer_class=self.__class__.__name__
                    )
                )
            return fields

        # 如果未指定`Meta.fields`，则使用缺省字段名称集。
        fields = self.get_default_field_names(declared_fields, info)

        if exclude is not None:
            # 如果包含`Meta.exclude`，则删除这些字段。
            for field_name in exclude:
                assert field_name not in self._declared_fields, (
                    "Cannot both declare the field '{field_name}' and include "
                    "it in the {serializer_class} 'exclude' option. Remove the "
                    "field or, if inherited from a parent serializer, disable "
                    "with `{field_name} = None`."
                    .format(
                        field_name=field_name,
                        serializer_class=self.__class__.__name__
                    )
                )

                assert field_name in fields, (
                    "The field '{field_name}' was included on serializer "
                    "{serializer_class} in the 'exclude' option, but does "
                    "not match any model field.".format(
                        field_name=field_name,
                        serializer_class=self.__class__.__name__
                    )
                )
                fields.remove(field_name)

        return fields

    def get_default_field_names(self, declared_fields, model_info):
        """
        如果未指定`Meta.fields`选项，则返回将使用的默认字段名称列表。
        """
        return (
            [model_info.pk.name] +
            list(declared_fields.keys()) +
            list(model_info.fields.keys()) +
            list(model_info.forward_relations.keys())
        )

    # 构造序列化程序字段的方法...

    def build_field(self, field_name, info, model_class, nested_depth):
        """
        返回（cls，kwargs）的两个元组来构建一个序列化器字段。
        """
        if field_name in info.fields_and_pk:
            model_field = info.fields_and_pk[field_name]
            return self.build_standard_field(field_name, model_field)

        elif field_name in info.relations:
            relation_info = info.relations[field_name]
            if not nested_depth:
                return self.build_relational_field(field_name, relation_info)
            else:
                return self.build_nested_field(field_name, relation_info, nested_depth)

        elif hasattr(model_class, field_name):
            return self.build_property_field(field_name, model_class)

        elif field_name == self.url_field_name:
            return self.build_url_field(field_name, model_class)

        return self.build_unknown_field(field_name, model_class)

    def build_standard_field(self, field_name, model_field):
        """
        创建常规模型字段。
        """
        field_mapping = ClassLookupDict(self.serializer_field_mapping)

        field_class = field_mapping[model_field]
        field_kwargs = get_field_kwargs(field_name, model_field)

        # 当OneToOneField也是主键时的特殊情况
        if model_field.one_to_one and model_field.primary_key:
            field_class = self.serializer_related_field
            field_kwargs['queryset'] = model_field.related_model.objects

        if 'choices' in field_kwargs:
            # 有选择的字段被强制转换为“ChoiceField”，而不是使用常规字段。
            field_class = self.serializer_choice_field
            # 一些模型字段可能会引入对于选择字段无效的kwargs。 我们需要去掉这些。
            # Eg.models.DecimalField（max_digits= 3，decimal_places= 1，choices= DECIMAL_CHOICES）
            valid_kwargs = {
                'read_only', 'write_only',
                'required', 'default', 'initial', 'source',
                'label', 'help_text', 'style',
                'error_messages', 'validators', 'allow_null', 'allow_blank',
                'choices'
            }
            for key in list(field_kwargs.keys()):
                if key not in valid_kwargs:
                    field_kwargs.pop(key)

        if not issubclass(field_class, ModelField):
            # `model_field`只适用于`ModelField`的回退情况，当没有其他类型的字段与模型字段相匹配时使用。
            field_kwargs.pop('model_field', None)

        if not issubclass(field_class, CharField) and not issubclass(field_class, ChoiceField):
            # `allow_blank`只对文本字段有效。
            field_kwargs.pop('allow_blank', None)

        if postgres_fields and isinstance(model_field, postgres_fields.ArrayField):
            # 在为PostgreSQL特定的`ArrayField`生成的`ListField`实例上填充`child`参数。
            child_model_field = model_field.base_field
            child_field_class, child_field_kwargs = self.build_standard_field(
                'child', child_model_field
            )
            field_kwargs['child'] = child_field_class(**child_field_kwargs)

        return field_class, field_kwargs

    def build_relational_field(self, field_name, relation_info):
        """
        为前向和反向关系创建字段。
        """
        field_class = self.serializer_related_field
        field_kwargs = get_relation_kwargs(field_name, relation_info)

        to_field = field_kwargs.pop('to_field', None)
        if to_field and not relation_info.reverse and not relation_info.related_model._meta.get_field(to_field).primary_key:
            field_kwargs['slug_field'] = to_field
            field_class = self.serializer_related_to_field

        # `view_name`只对超链接关系有效。
        if not issubclass(field_class, HyperlinkedRelatedField):
            field_kwargs.pop('view_name', None)

        return field_class, field_kwargs

    def build_nested_field(self, field_name, relation_info, nested_depth):
        """
        为正向和反向关系创建嵌套字段。
        """
        class NestedSerializer(ModelSerializer):
            class Meta:
                model = relation_info.related_model
                depth = nested_depth - 1
                fields = '__all__'

        field_class = NestedSerializer
        field_kwargs = get_nested_relation_kwargs(relation_info)

        return field_class, field_kwargs

    def build_property_field(self, field_name, model_class):
        """
        为模型方法和属性创建一个只读字段。
        """
        field_class = ReadOnlyField
        field_kwargs = {}

        return field_class, field_kwargs

    def build_url_field(self, field_name, model_class):
        """
        创建一个表示对象自己的URL的字段。
        """
        field_class = self.serializer_url_field
        field_kwargs = get_url_kwargs(model_class)

        return field_class, field_kwargs

    def build_unknown_field(self, field_name, model_class):
        """
        在任何未知字段上引发错误。
        """
        raise ImproperlyConfigured(
            'Field name `%s` is not valid for model `%s`.' %
            (field_name, model_class.__name__)
        )

    def include_extra_kwargs(self, kwargs, extra_kwargs):
        """
        包含此字段中包含的任何“extra_kwargs”，可能会删除任何不兼容的现有关键字参数。
        """
        if extra_kwargs.get('read_only', False):
            for attr in [
                'required', 'default', 'allow_blank', 'allow_null',
                'min_length', 'max_length', 'min_value', 'max_value',
                'validators', 'queryset'
            ]:
                kwargs.pop(attr, None)

        if extra_kwargs.get('default') and kwargs.get('required') is False:
            kwargs.pop('required')

        if extra_kwargs.get('read_only', kwargs.get('read_only', False)):
            extra_kwargs.pop('required', None)  # Read only fields should always omit the 'required' argument.

        kwargs.update(extra_kwargs)

        return kwargs

    # 用于确定要应用其他关键字参数的方法...

    def get_extra_kwargs(self):
        """
        将字典映射字段名称返回到其他关键字参数的字典中。
        """
        extra_kwargs = copy.deepcopy(getattr(self.Meta, 'extra_kwargs', {}))

        read_only_fields = getattr(self.Meta, 'read_only_fields', None)
        if read_only_fields is not None:
            if not isinstance(read_only_fields, (list, tuple)):
                raise TypeError(
                    'The `read_only_fields` option must be a list or tuple. '
                    'Got %s.' % type(read_only_fields).__name__
                )
            for field_name in read_only_fields:
                kwargs = extra_kwargs.get(field_name, {})
                kwargs['read_only'] = True
                extra_kwargs[field_name] = kwargs

        else:
            # 警惕可能拼写错误的`readonly_fields`（由Django管理员和其他人使用）。
            assert not hasattr(self.Meta, 'readonly_fields'), (
                'Serializer `%s.%s` has field `readonly_fields`; '
                'the correct spelling for the option is `read_only_fields`.' %
                (self.__class__.__module__, self.__class__.__name__)
            )

        return extra_kwargs

    def get_uniqueness_extra_kwargs(self, field_names, declared_fields, extra_kwargs):
        """
        返回需要作为模型唯一性约束结果的附加字段选项。 这返回为一个二元组：

       （'更新额外kwargs字典'，'隐藏字段映射'）
        """
        if getattr(self.Meta, 'validators', None) is not None:
            return (extra_kwargs, {})

        model = getattr(self.Meta, 'model')
        model_fields = self._get_model_fields(
            field_names, declared_fields, extra_kwargs
        )

        # 确定是否需要任何额外的`HiddenField`或额外的关键字参数来处理需要在输入数据中以验证它的`unique_for`日期。
        unique_constraint_names = set()

        for model_field in model_fields.values():
            # 包括每个`unique_for_ *`字段名称。
            unique_constraint_names |= {model_field.unique_for_date, model_field.unique_for_month,
                                        model_field.unique_for_year}

        unique_constraint_names -= {None}

        # 包含每个`unique_together`字段名称，只要所有字段名称都包含在序列化程序中。
        for parent_class in [model] + list(model._meta.parents.keys()):
            for unique_together_list in parent_class._meta.unique_together:
                if set(field_names).issuperset(set(unique_together_list)):
                    unique_constraint_names |= set(unique_together_list)

        # 现在我们已经应用了所有具有唯一性约束的字段名称，
        # 我们可以添加适合这些字段的额外“required = ...”或“default = ...”参数，
        # 或为其添加“HiddenField”。
        hidden_fields = {}
        uniqueness_extra_kwargs = {}

        for unique_constraint_name in unique_constraint_names:
            # 获取被引用的模型字段。
            unique_constraint_field = model._meta.get_field(unique_constraint_name)

            if getattr(unique_constraint_field, 'auto_now_add', None):
                default = CreateOnlyDefault(timezone.now)
            elif getattr(unique_constraint_field, 'auto_now', None):
                default = timezone.now
            elif unique_constraint_field.has_default():
                default = unique_constraint_field.default
            else:
                default = empty

            if unique_constraint_name in model_fields:
                # 相应的字段存在于serializer中
                if default is empty:
                    uniqueness_extra_kwargs[unique_constraint_name] = {'required': True}
                else:
                    uniqueness_extra_kwargs[unique_constraint_name] = {'default': default}
            elif default is not empty:
                # serializer中不存在相应的字段。 我们有一个默认的使用它，所以添加一个隐藏的领域，填充它。
                hidden_fields[unique_constraint_name] = HiddenField(default=default)

        # 使用任何新选项更新`extra_kwargs`。
        for key, value in uniqueness_extra_kwargs.items():
            if key in extra_kwargs:
                value.update(extra_kwargs[key])
            extra_kwargs[key] = value

        return extra_kwargs, hidden_fields

    def _get_model_fields(self, field_names, declared_fields, extra_kwargs):
        """
        返回序列化程序类中字段映射的所有模型字段。
        作为"模型字段名称"的字典返回 - >"模型字段"。
        由`get_uniqueness_field_options`内部使用。
        """
        model = getattr(self.Meta, 'model')
        model_fields = {}

        for field_name in field_names:
            if field_name in declared_fields:
                # 如果该字段在serializer上声明
                field = declared_fields[field_name]
                source = field.source or field_name
            else:
                try:
                    source = extra_kwargs[field_name]['source']
                except KeyError:
                    source = field_name

            if '.' in source or source == '*':
                # 模型字段将始终具有简单的源映射，但它们不能嵌套属性查找。
                continue

            try:
                field = model._meta.get_field(source)
                if isinstance(field, DjangoModelField):
                    model_fields[source] = field
            except FieldDoesNotExist:
                pass

        return model_fields

    # 确定要应用的验证器...

    def get_validators(self):
        """
        确定实例化序列化程序时使用的一组验证程序。
        """
        # 如果验证器已被明确声明，那就使用它。
        validators = getattr(getattr(self, 'Meta', None), 'validators', None)
        if validators is not None:
            return validators[:]

        # 否则使用默认的验证器集合。
        return (
            self.get_unique_together_validators() +
            self.get_unique_for_date_validators()
        )

    def get_unique_together_validators(self):
        """
        确定任何unique_together约束的默认验证程序集。
        """
        model_class_inheritance_tree = (
            [self.Meta.model] +
            list(self.Meta.model._meta.parents.keys())
        )

        # 我们在这里传递的字段名称仅包含可映射到模型字段的字段。
        # 任何虚线字段名称查找都无法映射到字段，并且必须是遍历的，
        # 所以我们不包含这些字段。
        field_names = {
            field.source for field in self._writable_fields
            if (field.source != '*') and ('.' not in field.source)
        }

        # 请注意，我们确保在基础模型类中检查`unique_together`，
        # 而且在任何父类上检查`unique_together`。
        validators = []
        for parent_class in model_class_inheritance_tree:
            for unique_together in parent_class._meta.unique_together:
                if field_names.issuperset(set(unique_together)):
                    validator = UniqueTogetherValidator(
                        queryset=parent_class._default_manager,
                        fields=unique_together
                    )
                    validators.append(validator)
        return validators

    def get_unique_for_date_validators(self):
        """
        确定以下约束的缺省验证器集合：

        * unique_for_date
        * unique_for_month
        * unique_for_year
        """
        info = model_meta.get_field_info(self.Meta.model)
        default_manager = self.Meta.model._default_manager
        field_names = [field.source for field in self.fields.values()]

        validators = []

        for field_name, field in info.fields_and_pk.items():
            if field.unique_for_date and field_name in field_names:
                validator = UniqueForDateValidator(
                    queryset=default_manager,
                    field=field_name,
                    date_field=field.unique_for_date
                )
                validators.append(validator)

            if field.unique_for_month and field_name in field_names:
                validator = UniqueForMonthValidator(
                    queryset=default_manager,
                    field=field_name,
                    date_field=field.unique_for_month
                )
                validators.append(validator)

            if field.unique_for_year and field_name in field_names:
                validator = UniqueForYearValidator(
                    queryset=default_manager,
                    field=field_name,
                    date_field=field.unique_for_year
                )
                validators.append(validator)

        return validators


if hasattr(models, 'UUIDField'):
    ModelSerializer.serializer_field_mapping[models.UUIDField] = UUIDField

# IPAddressField在Django中已弃用
if hasattr(models, 'IPAddressField'):
    ModelSerializer.serializer_field_mapping[models.IPAddressField] = IPAddressField

if postgres_fields:
    class CharMappingField(DictField):
        child = CharField(allow_blank=True)

    ModelSerializer.serializer_field_mapping[postgres_fields.HStoreField] = CharMappingField
    ModelSerializer.serializer_field_mapping[postgres_fields.ArrayField] = ListField
    ModelSerializer.serializer_field_mapping[postgres_fields.JSONField] = JSONField


class HyperlinkedModelSerializer(ModelSerializer):
    """
    一种“ModelSerializer”，它使用超链接关系而不是主键关系。 特别：

     *包含'url'字段而不是'id'字段。
     *与其他实例的关系是超链接，而不是主键。
    """
    serializer_related_field = HyperlinkedRelatedField

    def get_default_field_names(self, declared_fields, model_info):
        """
        如果未指定`Meta.fields`选项，则返回将使用的默认字段名称列表。
        """
        return (
            [self.url_field_name] +
            list(declared_fields.keys()) +
            list(model_info.fields.keys()) +
            list(model_info.forward_relations.keys())
        )

    def build_nested_field(self, field_name, relation_info, nested_depth):
        """
        为正向和反向关系创建嵌套字段。
        """
        class NestedSerializer(HyperlinkedModelSerializer):
            class Meta:
                model = relation_info.related_model
                depth = nested_depth - 1
                fields = '__all__'

        field_class = NestedSerializer
        field_kwargs = get_nested_relation_kwargs(relation_info)

        return field_class, field_kwargs
