from rest_framework import serializers
from rest_framework.serializers import ModelSerializer
from django.contrib.auth.models import Permission, Group
from .models import Bills, Categories, Dishes, DishesProducts, DishesVariants, Notifications, Orders, OrdersHasDishes, User

class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance
    def update(self, instance, validated_data):
        return super().update(instance, validated_data)
    
class UserDetailsSerializer(ModelSerializer):
    first_name = serializers.CharField(max_length=255, allow_null=True)
    last_name = serializers.CharField(max_length=255, allow_null=True)
    class Meta:
        model = User
        fields = ['id','hired_time', 'fired_time', 'phone_no', 'first_name', 'last_name', 'username', 'email', 'last_login']
        extra_kwargs = {
            'password': {'write_only': True},
            'last_login': {'read_only': True},
            'hired_time': {'read_only': True},
            'fired_time': {'read_only': True},
        }
    def update(self, instance, validated_data):
        new_password = validated_data.get('password')

        # Jeśli przekazano nowe hasło, ustaw je
        if new_password:
            instance.set_password(new_password)

        return super().update(instance, validated_data)
    
class CategoriesSerializer(ModelSerializer):
    class Meta:
        model = Categories
        fields = ['Category', 'name', 'higher_category']
        extra_kwargs = {
            'Category': {'read_only': True}
        }
    def create(self, validated_data):
        return super().create(validated_data)
    def update(self, instance, validated_data):
        return super().update(instance, validated_data)


class DishesSerializer(ModelSerializer):
    class Meta:
        model = Dishes
        fields = '__all__'
        extra_kwargs = {
            'D_no': {'read_only': True}
        }
    def create(self, validated_data):
        return super().create(validated_data)
    def update(self, instance, validated_data):
        return super().update(instance, validated_data)

class DishesProductsSerializer(ModelSerializer):
    class Meta:
        model = DishesProducts
        fields = '__all__'
    def create(self, validated_data):
        return super().create(validated_data)
    def update(self, instance, validated_data):
        return super().update(instance, validated_data)

class DishesVariantsSerializer(ModelSerializer):
    class Meta:
        model = DishesVariants
        fields = '__all__'
    def create(self, validated_data):
        return super().create(validated_data)
    def update(self, instance, validated_data):
        return super().update(instance, validated_data)

class OrdersDetailsSerializer(ModelSerializer):
    class Meta:
        model = Orders
        fields = '__all__'
    def create(self, validated_data):
        return super().create(validated_data)
    def update(self, instance, validated_data):
        return super().update(instance, validated_data)

class OrdershasDishesSerializer(ModelSerializer):
    dishes = DishesSerializer(many=True, read_only=True)
    variants = dishes = DishesVariantsSerializer(many=True, read_only=True)
    class Meta:
        model = OrdersHasDishes
        fields = ['count', 'done', 'dishes', 'variants']
    def create(self, validated_data):
        return super().create(validated_data)
    def update(self, instance, validated_data):
        return super().update(instance, validated_data)

class BillsSerializer(ModelSerializer):
    class Meta:
        model = Bills
        fields = '__all__'
    def create(self, validated_data):
        return super().create(validated_data)
    def update(self, instance, validated_data):
        return super().update(instance, validated_data)

class OrdersSerializer(ModelSerializer):
    dishes1 = OrdershasDishesSerializer(many=True, read_only=True)
    class Meta:
        model = Orders
        fields = ['Order', 'time', 'table', 'waiter','dishes1']

class OrdersHasDishesSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrdersHasDishes
        fields = '__all__'

class PendingOrderDetailsSerializer(serializers.ModelSerializer):
    Variant_no = serializers.CharField(source='Variant.Variant_no')
    Variant_count = serializers.DecimalField(source='Variant.count', max_digits=8, decimal_places=2)
    Dish_name = serializers.CharField(source='Dish.name')

    class Meta:
        model = OrdersHasDishes
        fields = ['Order', 'id', 'count', 'done', 'Variant_no', 'Variant_count', 'Dish_name', 'note']

class OrderStartSerializer(serializers.Serializer):
    table = serializers.CharField(max_length=4)

class OrderCreateSerializer(serializers.Serializer):
    dishes = serializers.ListField(write_only=True, child=serializers.IntegerField())
    order = serializers.IntegerField(write_only=True)
    counts = serializers.ListField(write_only=True, child=serializers.DecimalField(max_digits=8, decimal_places=2))
    variants = serializers.ListField(write_only=True, child=serializers.IntegerField())

class Permission2Serializer(serializers.Serializer):
    group_id = serializers.IntegerField(required=True)
    user_id = serializers.IntegerField(required=True)
    permission_codename = serializers.CharField(required=True)

class UserOrGroupPermissionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'name','codename']

class NotificationsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notifications
        fields = ['Notification_no', 'To', 'notification', 'status', 'Order']
        extra_kwargs = {
            'Notification_no': {'read_only': True}
        }

class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'name', 'codename']

class GroupSerializer(serializers.ModelSerializer):
    permissions = serializers.SerializerMethodField()

    def get_permissions(self, group):
        permissions = Permission.objects.filter(group=group)
        return PermissionSerializer(permissions, many=True).data

    class Meta:
        model = Group
        fields = ['id', 'name', 'permissions']

class GroupUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ['id','name']

class UserGroupSerializer(serializers.ModelSerializer):
    groups = GroupUserSerializer(many=True, read_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'groups']