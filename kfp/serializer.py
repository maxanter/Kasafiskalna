from rest_framework import serializers
from rest_framework.serializers import ModelSerializer
from django.contrib.auth.models import Permission
from .models import Bills, Categories, Dishes, DishesProducts, DishesVariants, Orders, OrdersHasDishes, User

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
    
class CategoriesSerializer(ModelSerializer):
    class Meta:
        model = Categories
        fields = '__all__'
    def create(self, validated_data):
        return super().create(validated_data)
    def update(self, instance, validated_data):
        return super().update(instance, validated_data)


class DishesSerializer(ModelSerializer):
    class Meta:
        model = Dishes
        fields = '__all__'
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
        fields = ['Order', 'time', 'waiter','dishes1']

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
        fields = ['Order', 'id', 'count', 'done', 'Variant_no', 'Variant_count', 'Dish_name']

class OrderStartSerializer(serializers.Serializer):
    waiter = serializers.IntegerField()

class OrderCreateSerializer(serializers.Serializer):
    dishes = serializers.ListField(write_only=True, child=serializers.IntegerField())
    order = serializers.IntegerField(write_only=True)
    counts = serializers.ListField(write_only=True, child=serializers.DecimalField(max_digits=8, decimal_places=2))
    variants = serializers.ListField(write_only=True, child=serializers.IntegerField())

class PermissionSerializer(serializers.Serializer):
    group_id = serializers.IntegerField(required=True)
    user_id = serializers.IntegerField(required=True)
    permission_codename = serializers.CharField(required=True)

class UserOrGroupPermissionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'name','codename']