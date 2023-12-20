from rest_framework import exceptions, status
from rest_framework.authentication import get_authorization_header
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.exceptions import APIException, AuthenticationFailed

from django.db.models import Q
from django.db import transaction

from .authentication import create_access_token, create_refresh_token, decode_access_token, decode_refresh_token
from .autorization import check_perms
from .serializer import BillsSerializer, CategoriesSerializer, DishesProductsSerializer, DishesSerializer, DishesVariantsSerializer, OrderCreateSerializer, OrderStartSerializer, OrdersDetailsSerializer, OrdersSerializer, PendingOrderDetailsSerializer, OrdersHasDishesSerializer, UserOrGroupPermissionsSerializer, UserSerializer, PermissionSerializer
from .models import Bills, Categories, Dishes, DishesProducts, DishesVariants, Orders, OrdersHasDishes, User
from django.contrib.auth.models import Group, Permission

class RegisterAPIView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class LoginAPIView(APIView):
    def post(self, request):
        user = User.objects.filter(username=request.data['username']).first()

        if not user:
            raise APIException('Invalid credentials!')

        if not user.check_password(request.data['password']):
            raise APIException('Invalid credentials!')

        access_token = create_access_token(user.id)
        refresh_token = create_refresh_token(user.id)

        response = Response()

        response.set_cookie(key='refreshToken', value=refresh_token, httponly=True)
        response.data = {
            'token': access_token
        }

        return response


class UserAPIView(APIView):
    def get(self, request):
        auth = get_authorization_header(request).split()

        if auth and len(auth) == 2:
            token = auth[1].decode('utf-8')
            id = decode_access_token(token)

            user = User.objects.filter(pk=id).first()

            return Response(UserSerializer(user).data)

        raise AuthenticationFailed('unauthenticated')

class RefreshApiView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        access_token = create_access_token(id)

        return Response({
            'token': access_token
        })
    
class LogoutApiView(APIView):
    def post(self, _):
        response = Response()
        response.delete_cookie(key="refreshToken")
        response.data = {
            'message': 'Success!'
        }
        return response
    
class CategoriesView(APIView):
    def get(self, request):
        requier_perms = ['view_categories']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        queryset = Categories.objects.all()
        serializer = CategoriesSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class DishesView(APIView):
    def get(self, request):
        requier_perms = ['view_dishes']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        queryset = Dishes.objects.all()
        serializer = DishesSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class DishesProductsView(APIView):
    def get(self, request):
        requier_perms = ['view_dishesproducts']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        queryset = DishesProducts.objects.all()
        serializer = DishesProductsSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class DishesVariantsView(APIView):
    def get(self, request):
        requier_perms = ['view_dishesvariants']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        queryset = DishesVariants.objects.all()
        serializer = DishesVariantsSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class OrdersDetailsView(APIView):
    def get(self, request):
        requier_perms = ['view_orders']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        queryset = Orders.objects.all()
        serializer = OrdersDetailsSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class OrdershasDishesView(APIView):
    def get(self, request):
        requier_perms = ['view_orders']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        queryset = OrdersHasDishes.objects.all()
        serializer = OrdersHasDishesSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class BillsView(APIView):
    def get(self, request):
        requier_perms = ['view_orders']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        queryset = Bills.objects.all()
        serializer = BillsSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class KitchenOrdersView(APIView):
    def get(self, request):
        requier_perms = ['view_orders', 'view_ordershasdishes']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        queryset = OrdersHasDishes.objects.filter(done=False).filter(
            Q(Order__isnull=False) & Q(Dish__isnull=False) & Q(Variant__isnull=False)
        )
        serializer = PendingOrderDetailsSerializer(queryset, many=True)
        return Response({'Orders': serializer.data})
    
class UpdateDoneStatusAPIView(APIView):
    def put(self, request, pk, format=None):
        requier_perms = ['change_ordershasdishes']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        try:
            order_has_dish = OrdersHasDishes.objects.get(pk=pk)
        except OrdersHasDishes.DoesNotExist:
            return Response({'error': 'OrderHasDishes not found'}, status=status.HTTP_404_NOT_FOUND)

        order_has_dish.done = True
        order_has_dish.save()

        serializer = OrdersHasDishesSerializer(order_has_dish)
        return Response(serializer.data)

class KitchenOrderStartView(APIView):
    def post(self, request):
        requier_perms = ['add_orders']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        serializer = OrderStartSerializer(data = request.data)
        if serializer.is_valid():
            waiter = serializer.validated_data['waiter']

            order = Orders.objects.create(waiter_id = waiter)
            
            latest_order = Orders.objects.filter(waiter=waiter).latest('time')

            print(latest_order.pk)
            response_data = {
                'Order': latest_order.pk
            }

            return Response(response_data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class KitchenOrderCreateView(APIView):
    @transaction.atomic
    def post(self, request):
        requier_perms = ['add_orders']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        serializer = OrderCreateSerializer(data=request.data)
        if serializer.is_valid():
            order_number = serializer.validated_data['order']
            dish_ids = serializer.validated_data['dishes']
            counts = serializer.validated_data['counts']
            variants = serializer.validated_data['variants']

            try:
                with transaction.atomic():
                    order = Orders.objects.get(pk=order_number)
                    for dish_id, count, variant_id in zip(dish_ids, counts, variants):
                        dish = Dishes.objects.get(pk=dish_id)
                        variant = DishesVariants.objects.get(pk=variant_id)

                        OrdersHasDishes.objects.create(Order=order, Dish=dish, count=count, Variant=variant, done=False)

                response_data = {
                    'message': 'Success'
                }

                return Response(response_data, status=status.HTTP_201_CREATED)

            except Exception as e:
                # W razie błędu, cofnij transakcję
                transaction.set_rollback(True)
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AddPermissionToGroup(APIView):
    def post(self, request):
        requier_perms = ['add_permission', 'change_group']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        serializer = PermissionSerializer(data=request.data)
        if serializer.is_valid():
            group_id = serializer.validated_data['group_id']
            permission_codename = serializer.validated_data['permission_codename']

            try:
                group = Group.objects.get(pk=group_id)
                permission = Permission.objects.get(codename=permission_codename)

                group.permissions.add(permission)

                return Response({'message': 'Permission added to group successfully'}, status=status.HTTP_200_OK)
            except Group.DoesNotExist:
                return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)
            except Permission.DoesNotExist:
                return Response({'error': 'Permission not found'}, status=status.HTTP_404_NOT_FOUND)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AddPermissionToUser(APIView):
    def post(self, request):
        requier_perms = ['add_permission', 'change_user']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        serializer = PermissionSerializer(data=request.data)
        if serializer.is_valid():
            user_id = serializer.validated_data['user_id']
            permission_codename = serializer.validated_data['permission_codename']

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

class RemovePermissionFromGroup(APIView):
    def post(self, request):
        requier_perms = ['delete_permission', 'change_group']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        serializer = PermissionSerializer(data=request.data)
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

class RemovePermissionFromUser(APIView):
    def post(self, request):
        requier_perms = ['delete_permission', 'change_user']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        serializer = PermissionSerializer(data=request.data)
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


class PermissionsView(APIView):
    def get(self, request):
        requier_perms = ['view_permission']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        permissions = Permission.objects.all()

        permissions_list = [
            {
            'id': permission.pk,
            'name': permission.name,
            'codename': permission.codename,
            }
            for permission in permissions
        ]

        return Response({'permissions': permissions_list})
    
class UserPermissionsView(APIView):
    def get(self, request, pk):
        requier_perms = ['view_permission', 'view_user']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        try:
            user = User.objects.get(pk=pk)
            permissions = user.user_permissions.all()
            serializer = UserOrGroupPermissionsSerializer(permissions, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

class GroupPermissionsView(APIView):
    def get(self, request, pk):
        requier_perms = ['view_permission', 'view_group']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        try:
            group = Group.objects.get(pk=pk)
            permissions = group.permissions.all()
            serializer = UserOrGroupPermissionsSerializer(permissions, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Group.DoesNotExist:
            return Response({'error': 'Group not found'}, status=status.HTTP_404_NOT_FOUND)


"""
    Lista enpointów do zrobienia:
        - get: całe menu
            czyli musiałbym wysłać kategorie w których były by menu, 
            w tym menu musiałyby być produkty i warianty
            1. Oddzielnie kategorie menu od warianty produkty
                czyli 3 endpointy
            2.wszystko połączone jako duża lista

            pierwszy jest bardziej rozsądny, żeby nie przesyłać zbyt dużych paczek danych

"""