from django.contrib.auth.models import Group, Permission
from django.db.models import Q, Sum
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings
from rest_framework import status, exceptions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import APIException
from .models import (Categories, Dishes, DishesProducts, 
                    DishesVariants, Orders, OrdersHasDishes, 
                    Bills, Notifications, User)
from .serializer import (BillsSerializer, CategoriesSerializer, 
                        DishesProductsSerializer, DishesSerializer, 
                        DishesVariantsSerializer, NotificationsSerializer,
                        OrderStartSerializer, OrdersDetailsSerializer, 
                        PendingOrderDetailsSerializer, OrdersHasDishesSerializer, 
                        UserDetailsSerializer, PermissionSerializer, 
                        UserSerializer, Permission2Serializer, GroupSerializer)
from datetime import timedelta
from .autorization import check_perms
from .authentication import create_access_token, create_refresh_token, decode_refresh_token

class PermissionRequiredMixin:
    required_permissions = []

    def check_permissions(self, request):
        refresh_token = request.headers.get('Authorization').split(' ')[1] if 'Authorization' in request.headers else None
        print(refresh_token)
        id = decode_refresh_token(refresh_token)
        print(self.required_permissions)
        if not check_perms(id, self.required_permissions):
            raise exceptions.PermissionDenied('Access denied')
        return id

class RegisterLoginAPIView(APIView):
    required_permissions = []

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    
    def get(self, request):
        user = User.objects.filter(username=request.data['username']).first()

        if not user:
            raise APIException('Invalid credentials!')

        if not user.check_password(request.data['password']):
            raise APIException('Invalid credentials!')

        if user.is_active == False:
            raise APIException('Invalid credentials!')

        user.last_login = timezone.now() + timedelta(hours=1)
        user.save()
        print(user.id)
        access_token = create_access_token(user.id)
        refresh_token = create_refresh_token(user.id)

        response = Response()

        response.set_cookie(key='refreshToken', value=refresh_token, httponly=True)
        response.data = {
            'token': access_token,
            'refreshToken': refresh_token
        }
        return response
    
    def delete(self, request):
        refresh_token = request.headers.get('Authorization').split(' ')[1] if 'Authorization' in request.headers else None
        id = decode_refresh_token(refresh_token)
        user = User.objects.get(pk = id)
        user.last_login = timezone.now() + timedelta(hours=1)
        user.save()
        response = Response()
        response.delete_cookie(key="refreshToken")
        response.data = {
            'message': 'Success!'
        }
        return response
    
class UserAPIView(PermissionRequiredMixin, APIView):
    def get(self, request):
        id = self.check_permissions(request)
        user = User.objects.filter(pk=id).first()

        serializer = UserDetailsSerializer(user)

        return Response(serializer.data)


class CategoriesView(PermissionRequiredMixin, APIView):
    required_permissions = []
    def get(self, request, pk, hk):
        self.required_permissions = ['view_categories']
        id = self.check_permissions(request)

        cache_key = f'categories_{pk}_{hk}'
        queryset = cache.get(cache_key)
        if queryset is None:
            if hk == 0:
                queryset = Categories.objects.filter(pk=pk) if pk != 0 else Categories.objects.all()
            else:
                queryset = Categories.objects.filter(higher_category=hk)

            cache.set(cache_key, queryset, timeout=settings.CACHE_TIMEOUT)

        serializer = CategoriesSerializer(queryset, many=True)
        return Response(serializer.data)
    
    def post(self, request, format=None):
        self.required_permissions = ['add_categories']
        id = self.check_permissions(request)
        serializer = CategoriesSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            category = Categories.objects.get(name = request.data.get('name'))
            serializer2 = DishesSerializer(category, many = False)
            return Response(serializer2.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk, format=None):
        self.required_permissions = ['change_categories']
        id = self.check_permissions(request)
        category = Categories.objects.get(pk=pk)
        serializer = CategoriesSerializer(category, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    def delete(self, request, pk, format=None):
        self.required_permissions = ['delete_categories']
        id = self.check_permissions(request)
        queryset = Categories.objects.get(pk=pk)
        queryset.delete()
        return Response({'message':'success'},status=status.HTTP_204_NO_CONTENT)


class DishesView(PermissionRequiredMixin, APIView):
    required_permissions = []
    def get(self, request, pk, kk):
        self.required_permissions = ['view_dishes']
        id = self.check_permissions(request)

        cache_key = f'dishes_{pk}_{kk}'
        queryset = cache.get(cache_key)

        if queryset is None:
            if kk == 0:
                queryset = Dishes.objects.filter(D_no=pk).select_related('category') if pk != 0 else Dishes.objects.all().select_related('category')
            else:
                queryset = Dishes.objects.filter(category=kk).select_related('category')
            cache.set(cache_key, queryset, timeout=settings.CACHE_TIMEOUT)
        serializer = DishesSerializer(queryset, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        self.required_permissions = ['add_dishes']
        id = self.check_permissions(request)
        serializer = DishesSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            dish = Dishes.objects.get(name = request.data.get('name'))
            serializer2 = DishesSerializer(dish, many = False)
            return Response(serializer2.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk, format=None):
        self.required_permissions = ['change_dishes']
        id = self.check_permissions(request)
        dish = Dishes.objects.get(pk=pk)
        serializer = DishesSerializer(dish, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        self.required_permissions = ['delete_dishes']
        id = self.check_permissions(request)
        queryset = Dishes.objects.get(pk=pk)
        queryset.delete()
        return Response({'message':'success'},status=status.HTTP_204_NO_CONTENT)

class DishesProductsView(PermissionRequiredMixin, APIView):
    required_permissions = []
    def get(self, request, pk, dk):
        self.required_permissions = ['view_dishesproducts']
        id = self.check_permissions(request)

        cache_key = f'dishes_products_{pk}_{dk}'
        queryset = cache.get(cache_key)
        if queryset is None:
            if dk == 0:
                queryset = DishesProducts.objects.filter(pk=pk).select_related('Dish') if pk != 0 else DishesProducts.objects.all().select_related('Dish')
            else:
                queryset = DishesProducts.objects.filter(Dish=dk).select_related('Dish')
            cache.set(cache_key, queryset, timeout=settings.CACHE_TIMEOUT)
        serializer = DishesProductsSerializer(queryset, many=True)
        return Response(serializer.data)
    
    def post(self, request, format=None):
        self.required_permissions = ['add_dishesproducts']
        id = self.check_permissions(request)
        serializer = DishesProductsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk, format=None):
        self.required_permissions = ['change_dishesproducts']
        id = self.check_permissions(request)
        dishes_products = DishesProducts.objects.get(pk=pk)
        serializer = DishesProductsSerializer(dishes_products, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        self.required_permissions = ['delete_dishesproducts']
        id = self.check_permissions(request)
        queryset = DishesProducts.objects.get(pk=pk)
        queryset.delete()
        return Response({'message':'success'},status=status.HTTP_204_NO_CONTENT)


class DishesVariantsView(PermissionRequiredMixin, APIView):
    required_permissions = []
    def get(self, request, pk, dk):
        self.required_permissions = ['view_dishesvariants']
        id = self.check_permissions(request)
        
        cache_key = f'dishes_variants_{pk}_{dk}'
        queryset = cache.get(cache_key)
        
        if queryset is None:
            if dk == 0:
                queryset = DishesVariants.objects.filter(pk=pk).select_related('Dish') if pk != 0 else DishesVariants.objects.all().select_related('Dish')
            else:
                queryset = DishesVariants.objects.filter(Dish=dk).select_related('Dish')
            cache.set(cache_key, queryset, timeout=settings.CACHE_TIMEOUT)
        
        serializer = DishesVariantsSerializer(queryset, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        self.required_permissions = ['add_dishesvariants']
        id = self.check_permissions(request)
        serializer = DishesVariantsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk, format=None):
        self.required_permissions = ['change_dishesvariants']
        id = self.check_permissions(request)
        dishes_variants = DishesVariants.objects.get(pk=pk)
        serializer = DishesVariantsSerializer(dishes_variants, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        self.required_permissions = ['delete_dishesvariants']
        id = self.check_permissions(request)
        queryset = DishesVariants.objects.get(pk=pk)
        queryset.delete()
        return Response({'message':'success'},status=status.HTTP_204_NO_CONTENT)


class OrdersDetailsView(PermissionRequiredMixin, APIView):
    required_permissions = []
    def get(self, request, pk, uk):
        self.required_permissions = ['view_orders']
        id = self.check_permissions(request)
        if uk == 0:
            if pk == 0:
                queryset = Orders.objects.select_related('waiter').prefetch_related('ordershasdishes_set').filter(bills__isnull=True)
            else:
                queryset = Orders.objects.select_related('waiter').prefetch_related('ordershasdishes_set').filter(pk=pk, bills__isnull=True)
        else:
            queryset = Orders.objects.select_related('waiter').prefetch_related('ordershasdishes_set').filter(waiter = uk, bills__isnull=True)
        serializer = OrdersDetailsSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK) 

    def delete(self, request, pk):
        self.required_permissions = ['delete_orders']
        id = self.check_permissions(request)
        Order = get_object_or_404(Orders, pk = pk)

        if OrdersHasDishes.objects.filter(Order = pk).exists():
            return Response({'error': 'Nie można usunąć zamówienia, które posiada pozycje'}, status=status.HTTP_400_BAD_REQUEST)
        Order.delete()

        return Response({'message': 'Zamówienie zostało pomyślnie usunięte'}, status=status.HTTP_200_OK)


class OrdershasDishesView(PermissionRequiredMixin, APIView):
    required_permissions = []
    def get(self, request, pk, ok):
        self.required_permissions = ['view_orders']
        id = self.check_permissions(request)
        if ok == 0:
            if pk == 0:
                queryset = OrdersHasDishes.objects.all()
            else:
                queryset = OrdersHasDishes.objects.filter(pk=pk)
        else: 
            queryset = OrdersHasDishes.objects.filter(Order = ok)
            
        serializer = OrdersHasDishesSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def delete(self, request, pk):
        self.required_permissions = ['delete_orders']
        id = self.check_permissions(request)
        Order = get_object_or_404(OrdersHasDishes, pk=pk)

        if Order.done == True:
            return Response({'error': 'Nie można usunąć Zamówienia, które zostało już wykonane!'}, status=status.HTTP_400_BAD_REQUEST)
        Order.delete()

        return Response({'message': 'Zamówienie zostało pomyślnie usunięte'}, status=status.HTTP_200_OK)

class BillsView(PermissionRequiredMixin, APIView):
    required_permissions = []
    def get(self, request, pk, uk):
        self.required_permissions = ['view_orders']
        id = self.check_permissions(request)
        if uk == 0:
            if pk == 0:
                queryset = Bills.objects.all().select_related('order', 'waiter')
            else:
                queryset = Bills.objects.get(pk=pk)
        else:
            queryset = Bills.objects.filter(waiter = uk).select_related('order', 'waiter')
           
        serializer = BillsSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, pk):
        self.required_permissions = ['add_bills']
        id = self.check_permissions(request)
        if Orders.objects.filter(pk = pk).exists() == False:
            return Response({'error': 'Nie ma takiego zamówienia'}, status=status.HTTP_404_NOT_FOUND)
        if OrdersHasDishes.objects.filter(Order = pk).exists() == False:
            return Response({'error': 'To zamówienie nie ma pozycji'}, status=status.HTTP_404_NOT_FOUND)
        total_cost = OrdersHasDishes.objects.filter(Order_id=pk).aggregate(Sum('Dish__Cost'))['Dish__Cost__sum']
        order = Orders.objects.get(Order = pk)
        waiter = User.objects.get(pk = id)
        if Bills.objects.filter(order = order).exists():
            return Response({'error': 'Taki rachunek już istnieje'}, status=status.HTTP_400_BAD_REQUEST)
        Bills.objects.create(order = order, waiter = waiter, Cost = total_cost)
        
        ofbill = Bills.objects.get(order = order)
        serializer = BillsSerializer(ofbill, many = False)
        return Response(serializer.data, status=status.HTTP_200_OK)


class KitchenOrdersView(PermissionRequiredMixin, APIView):
    required_permissions = []
    def get(self, request, pk):
        self.required_permissions = ['view_orders', 'view_ordershasdishes']
        id = self.check_permissions(request)
        if pk==0:
            queryset = OrdersHasDishes.objects.filter(done=False).select_related('Order', 'Dish', 'Variant').filter(
                Q(Order__isnull=False) & Q(Dish__isnull=False) & Q(Variant__isnull=False)
            )
        else:
            queryset = OrdersHasDishes.objects.filter(done=False, Order=pk).filter(
                Q(Order__isnull=False) & Q(Dish__isnull=False) & Q(Variant__isnull=False)
            )
        serializer = PendingOrderDetailsSerializer(queryset, many=True)
        return Response(serializer.data)
    
    def put(self, request, pk, format=None):
        self.required_permissions = ['change_ordershasdishes']
        id = self.check_permissions(request)
        try:
            order_has_dish = OrdersHasDishes.objects.get(pk=pk)
        except OrdersHasDishes.DoesNotExist:
            return Response({'error': 'OrderHasDishes not found'}, status=status.HTTP_404_NOT_FOUND)

        order_has_dish.done = True
        order_has_dish.save()

        serializer = OrdersHasDishesSerializer(order_has_dish)
        return Response(serializer.data)
    
    def post(self, request):
        self.required_permissions = ['add_orders']
        id = self.check_permissions(request)
        serializer = OrderStartSerializer(data = request.data)
        if serializer.is_valid():
            table = serializer.validated_data['table']
            Orders.objects.create(waiter_id = id, table = table)
            latest_order = Orders.objects.filter(waiter=id).latest('time')

            response_data = {
                'Order': latest_order.pk
            }

            return Response(response_data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @transaction.atomic
    def patch(self, request):
        self.required_permissions = ['add_orders']
        id = self.check_permissions(request)
        serializer = OrdersHasDishesSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            response_data = {
                'message': 'Success' 
            }
            return Response(response_data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class GroupView(PermissionRequiredMixin, APIView):
    required_permissions = []
    def get(self, request,pk,uk):
        self.required_permissions = ['view_group']
        id = self.check_permissions(request)
        
        cache_key = f'group_{pk}_{uk}'
        group = cache.get(cache_key)
        
        if group is None:
            if uk == 0:
                if pk == 0:
                    group = Group.objects.all().prefetch_related('permissions')
                else:
                    group = Group.objects.filter(pk=pk).prefetch_related('permissions')
            else:
                user = User.objects.get(pk=uk)
                group = user.groups.all().prefetch_related('permissions')
            cache.set(cache_key, group, timeout=settings.CACHE_TIMEOUT)
        serializer = GroupSerializer(group, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        self.required_permissions = ['add_group']
        id = self.check_permissions(request)
        group_name = request.data.get('group_name')
        
        # Sprawdź, czy grupa o takiej nazwie już istnieje
        if Group.objects.filter(name=group_name).exists():
            return Response({'error': 'Grupa o tej nazwie już istnieje'}, status=status.HTTP_400_BAD_REQUEST)

        # Utwórz nową grupę
        new_group = Group.objects.create(name=group_name)
        new_group.save()

        return Response({'message': 'Nowa grupa została pomyślnie utworzona'}, status=status.HTTP_201_CREATED)

    def delete(self, request, pk):
        self.required_permissions = ['delete_group']
        id = self.check_permissions(request)
        group = get_object_or_404(Group, pk=pk)

        # Sprawdź, czy grupa nie jest używana przed usunięciem
        if User.objects.filter(groups=group).exists():
            return Response({'error': 'Nie można usunąć grupy, która jest przypisana do użytkowników'}, status=status.HTTP_400_BAD_REQUEST)

        group.delete()

        return Response({'message': 'Grupa została pomyślnie usunięta'}, status=status.HTTP_200_OK)
 

class GroupPermisionsView(PermissionRequiredMixin, APIView):
    required_permissions = []
    def get(self, request, pk, perm):
        self.required_permissions = ['view_permission', 'view_group']
        id = self.check_permissions(request)
        try:
            group = Group.objects.get(pk=pk)
            
            perm_bool = perm.lower() == 'true'
            if perm_bool:
                permissions = Permission.objects.exclude(id__in=group.permissions.values_list('id', flat=True))
            else:
                permissions = group.permissions.all()
            
            serializer = PermissionSerializer(permissions, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Group.DoesNotExist:
            return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)
    
    
    def post(self, request):
        self.required_permissions = ['add_permission', 'change_group']
        id = self.check_permissions(request)
        serializer = Permission2Serializer(data=request.data, partial=True)
        if serializer.is_valid():
            group_id = serializer.validated_data.get('group_id')
            permission_codename = serializer.validated_data.get('permission_codename')
            try:
                group = Group.objects.get(id=group_id)
                permission = Permission.objects.get(codename=permission_codename)

                group.permissions.add(permission)

                return Response({'message': 'Permission added to group successfully'}, status=status.HTTP_200_OK)
            except Group.DoesNotExist:
                return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)
            except Permission.DoesNotExist:
                return Response({'error': 'Permission not found'}, status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        self.required_permissions = ['delete_permission', 'change_group']
        id = self.check_permissions(request)
        serializer = Permission2Serializer(data=request.data, partial=True)
        if serializer.is_valid():
            group_id = serializer.validated_data['group_id']
            permission_codename = serializer.validated_data['permission_codename']

            try:
                group = Group.objects.get(pk=group_id)
                permission = Permission.objects.get(codename=permission_codename)

                group.permissions.remove(permission)

                return Response({'message': 'Permission removed from group successfully'}, status=status.HTTP_200_OK)
            except Group.DoesNotExist:
                return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)
            except Permission.DoesNotExist:
                return Response({'error': 'Permission not found'}, status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserPermissionsView(PermissionRequiredMixin, APIView):
    required_permissions = []
    def get(self, request, pk, perm):
        self.required_permissions = ['view_permission', 'view_user']
        id = self.check_permissions(request)

        try:
            user = User.objects.get(pk=pk)
            
            perm_bool = perm.lower() == 'true'
            if perm_bool:
                permissions = Permission.objects.exclude(id__in=user.user_permissions.values_list('id', flat=True))
            else:
                permissions = user.user_permissions.all()
            
            serializer = PermissionSerializer(permissions, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    
    def post(self, request):
        self.required_permissions = ['add_permission', 'change_user']
        id = self.check_permissions(request)
        serializer = Permission2Serializer(data=request.data, partial=True)
        if serializer.is_valid():
            user_id = serializer.validated_data.get('user_id')
            permission_codename = serializer.validated_data.get('permission_codename')
            try:
                user = User.objects.get(pk=user_id)
                permission = Permission.objects.get(codename=permission_codename)

                user.user_permissions.add(permission)

                return Response({'message': 'Permission added to user successfully'}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            except Permission.DoesNotExist:
                return Response({'error': 'Permission not found'}, status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request):
        self.required_permissions = ['delete_permission', 'change_user']
        id = self.check_permissions(request)
        serializer = Permission2Serializer(data=request.data, partial=True)
        if serializer.is_valid():
            user_id = serializer.validated_data['user_id']
            permission_codename = serializer.validated_data['permission_codename']

            try:
                user = User.objects.get(pk=user_id)
                permission = Permission.objects.get(codename=permission_codename)

                user.user_permissions.remove(permission)

                return Response({'message': 'Permission removed from user successfully'}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
            except Permission.DoesNotExist:
                return Response({'error': 'Permission not found'}, status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PermissionsView(PermissionRequiredMixin, APIView):
    required_permissions = []
    def get(self, request):
        self.required_permissions = ['view_permission']
        id = self.check_permissions(request)
        permissions = Permission.objects.all()

        permissions_list = [
            {
            'id': permission.pk,
            'name': permission.name,
            'codename': permission.codename,
            }
            for permission in permissions
        ]

        return Response({'permissions': permissions_list}, status=status.HTTP_200_OK)

class UserGroupView(PermissionRequiredMixin, APIView):
    required_permissions = []
    def get(self, request, pk, is_member):
        self.required_permissions = ['view_group', 'view_user']
        id = self.check_permissions(request)
        try:
            group_id = int(pk)
        except ValueError:
            return Response({'error': 'Invalid value for pk'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            group = Group.objects.get(pk=group_id)
        except Group.DoesNotExist:
            return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)

        if is_member.lower() == 'true':
            users = User.objects.filter(groups=group).prefetch_related('groups')
        elif is_member.lower() == 'false':
            users = User.objects.exclude(groups=group).prefetch_related('groups')
        else:
            return Response({'error': 'Invalid value for is_member'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = UserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, uk, gk):
        self.required_permissions = ['change_group']
        id = self.check_permissions(request)
        user = get_object_or_404(User, id=uk)
        group = get_object_or_404(Group, id=gk)

        user.groups.add(group)
        user.save()

        return Response({"detail": "User added to group successfully"}, status=status.HTTP_200_OK)

    def delete(self, request, uk, gk):
        self.required_permissions = ['change_group']
        id = self.check_permissions(request)
        user = get_object_or_404(User, id=uk)
        group = get_object_or_404(Group, id=gk)

        user.groups.remove(group)
        user.save()

        return Response({"detail": "User removed from group successfully"}, status=status.HTTP_200_OK)



class NotificationsView(PermissionRequiredMixin, APIView):
    required_permissions = []
    def put(self, request, pk):
        self.required_permissions = ['change_notifications']
        id = self.check_permissions(request)
        try:
            notification = Notifications.objects.get(pk=pk)
            if request.user != notification.To:
                raise exceptions.PermissionDenied('Access denied')
            notification.status = 2
            notification.save()
            return Response({"message": "success"})
        except Notifications.DoesNotExist:
            return Response({'error': 'Notification not found'}, status=status.HTTP_404_NOT_FOUND)
    def post(self, request):
        self.required_permissions = ['add_notifications']
        id = self.check_permissions(request)
        serializer = NotificationsSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'message': 'Success'})
    
    def get(self, request):
        self.required_permissions = ['view_notifications']
        id = self.check_permissions(request)
        create_notifications()
        notifications = Notifications.objects.filter(To=request.user, status__in=[1, 2]).select_related('To', 'Order').order_by('-time')
        serializer = NotificationsSerializer(notifications, many=True)
        return Response(serializer.data)
    
    def patch(self, request):
        self.required_permissions = ['view_notifications']
        id = self.check_permissions(request)
        if Notifications.objects.filter(To = id).exclude( status = 2).exists():
            noti = True
        else:
            noti = False
        return Response({'notification': noti}, status=status.HTTP_200_OK)

class UserView(PermissionRequiredMixin, APIView):
    required_permissions = []
    def get(self, request, pk, gk):
        self.required_permissions = ['view_user']
        id = self.check_permissions(request)
        
        if gk == 0:
            if pk == 0:
                queryset = User.objects.all()
            else:
                queryset = User.objects.get(pk = pk)
        else:
            group = Group.objects.get(pk = gk)
            queryset = User.objects.filter(groups__in=[group])


        if not queryset:
            raise exceptions.NotFound("Nie znaleziono użytkownika")
        if pk == 0:
            serializer = UserDetailsSerializer(queryset, many = True)
        else:
            serializer = UserDetailsSerializer(queryset, many = False)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def put(self, request, pk):
        self.required_permissions = ['change_user']
        id = self.check_permissions(request)
        user = get_object_or_404(User, pk=pk)

        user.is_active = False
        user.fired_time = timezone.now().date()
        user.save()

        return Response({'message': 'Użytkownik został pomyślnie dezaktywowany'}, status=status.HTTP_200_OK)

    def patch(self, request, pk):
        self.required_permissions = ['change_user']
        id = self.check_permissions(request)
        
        user = get_object_or_404(User, pk=pk)
        serializer = UserDetailsSerializer(user, data=request.data, partial=True)
        
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Dane użytkownika zostały pomyślnie zaktualizowane'}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    def delete(self, request, pk):
        self.required_permissions = ['delete_user']
        id = self.check_permissions(request)
        user = get_object_or_404(User, pk=pk)

        user.delete()

        return Response({'message': 'Użytkownik został pomyślnie usunięty'}, status=status.HTTP_200_OK)


def create_notifications():
    today = timezone.now().date()
    start_of_day = timezone.datetime.combine(today, timezone.datetime.min.time())
    end_of_day = timezone.datetime.combine(today, timezone.datetime.max.time())
    orders_to_notify = Orders.objects.filter(
        Q(time__gte=start_of_day) & Q(time__lte=end_of_day) & Q(ordershasdishes__done=True)
    ).distinct()

    if not orders_to_notify.exists():
        return

    notifications_to_create = []
    for order in orders_to_notify:
        dishes_count = OrdersHasDishes.objects.filter(Order=order, done=True).count()
        existing_notifications_count = Notifications.objects.filter(Order=order).count()
        remaining_notifications = dishes_count - existing_notifications_count

        if remaining_notifications > 0:
            user = User.objects.get(pk=order.waiter_id)
            notifications_to_create.extend([
                Notifications(
                    To=user,
                    notification='Gotowe',
                    status=Notifications.Status.WARNING,
                    Order=order
                ) for _ in range(remaining_notifications)
            ])

    Notifications.objects.bulk_create(notifications_to_create)
