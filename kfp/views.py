from datetime import timedelta
from rest_framework import exceptions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.exceptions import APIException 
from django.utils import timezone
from django.db.models import Q, Sum
from django.db import transaction
from django.shortcuts import get_object_or_404

from .authentication import create_access_token, create_refresh_token, decode_refresh_token
from .autorization import check_perms
from .serializer import BillsSerializer, CategoriesSerializer, DishesProductsSerializer, DishesSerializer, DishesVariantsSerializer, NotificationsSerializer, OrderCreateSerializer, OrderStartSerializer, OrdersDetailsSerializer, PendingOrderDetailsSerializer, OrdersHasDishesSerializer, UserDetailsSerializer, UserOrGroupPermissionsSerializer, UserSerializer, PermissionSerializer
from .models import Bills, Categories, Dishes, DishesProducts, DishesVariants, Notifications, Orders, OrdersHasDishes, User
from django.contrib.auth.models import Group, Permission

#dodatkowe funkcje
def create_notifications():
    orders_to_notify = Orders.objects.filter(ordershasdishes__done=True)

    notifications_to_create = []
    for order in orders_to_notify:
        existing_notifications_count = Notifications.objects.filter(Order=order).count()
        dishes_count = OrdersHasDishes.objects.filter(Order=order, done=True).count()

        remaining_notifications = dishes_count - existing_notifications_count

        if remaining_notifications > 0:
            existing_notification_orders = Notifications.objects.filter(Order=order).values_list('Order_id', flat=True)
            remaining_notification_orders = set(OrdersHasDishes.objects.filter(Order=order, done=True).values_list('Order_id', flat=True))
            user = User.objects.get(pk = order.waiter_id)
            notifications_to_create.extend([
                Notifications(
                    To=user,
                    notification='Gotowe',
                    status=Notifications.Status.WARNING,
                    Order=order
                ) for _ in range(remaining_notifications) if order.Order not in existing_notification_orders
            ])

    Notifications.objects.bulk_create(notifications_to_create)



#Rejestracja użytkownika
class RegisterAPIView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

#Logowanie użytkownika
class LoginAPIView(APIView):
    def post(self, request):
        user = User.objects.filter(username=request.data['username']).first()

        if not user:
            raise APIException('Invalid credentials!')

        if not user.check_password(request.data['password']):
            raise APIException('Invalid credentials!')

        if user.is_active == False:
            raise APIException('Invalid credentials!')

        user.last_login = timezone.now() + timedelta(hours=1)
        user.save()

        access_token = create_access_token(user.id)
        refresh_token = create_refresh_token(user.id)

        response = Response()

        response.set_cookie(key='refreshToken', value=refresh_token, httponly=True)
        response.data = {
            'token': access_token,
            'refreshToken': refresh_token
        }

        return response

#Prośba o dane użytkownika
class UserAPIView(APIView):
    def get(self, request):
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        
        user = User.objects.filter(pk=id).first()

        return Response(UserDetailsSerializer(user).data)

#Prośba o wygenerowanie tokenu dostępu
class RefreshApiView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        access_token = create_access_token(id)

        user = User.objects.get(pk = id)
        user.last_login = timezone.now() + timedelta(hours=1)
        user.save()

        return Response({
            'token': access_token
        })

#Prośba o usunięcie tokenu odświeżania
class LogoutApiView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get('refreshToken')
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
    
#Prośba o wyświetlenie wszystkich lub wybranej kategorii
class CategoriesView(APIView):
    def get(self, request, pk, hk):
        requier_perms = ['view_categories']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        if hk == 0:
            if pk == 0:
                queryset = Categories.objects.all()
            else:
                queryset = Categories.objects.filter(pk=pk)
        else:
            queryset = Categories.objects.filter(higher_category = hk)   
        serializer = CategoriesSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
                 
#Prośba o wyświetlenie wszystkich lub wybranej pozycji z menu
class DishesView(APIView):
    def get(self, request, pk, kk):
        requier_perms = ['view_dishes']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        if kk == 0:
            if pk == 0:
                queryset = Dishes.objects.all()
            else:
                queryset = Dishes.objects.filter(D_no=pk)
        else:
            queryset = Dishes.objects.filter(category = kk)
            
        serializer = DishesSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

#Prośba o wyświetlenie wszytswkich produktów lub produktów należących do jednaj pozycji w menu
class DishesProductsView(APIView):
    def get(self, request, pk, dk):
        requier_perms = ['view_dishesproducts']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        if dk == 0:
            if pk == 0:
                queryset = DishesProducts.objects.all()
            else:
                queryset = DishesProducts.objects.filter(pk=pk)
        else:
            queryset = DishesProducts.objects.filter(Dish=dk)
        serializer = DishesProductsSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


#Prośba o wyświetlenie wszytswkich wariantów lub wariantów należących do jednaj pozycji w menu
class DishesVariantsView(APIView):
    def get(self, request, pk, dk):
        requier_perms = ['view_dishesvariants']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        if dk == 0:
            if pk == 0:
                queryset = DishesVariants.objects.all()
            else:
                queryset = DishesVariants.objects.filter(pk=pk)
        else:
            queryset = DishesVariants.objects.filter(Dish=dk)
        serializer = DishesVariantsSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

#Prośba o wyświetlenie wszystkich lub wybranego zamówienia
class OrdersDetailsView(APIView):
    def get(self, request, pk, uk):
        requier_perms = ['view_orders']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        if uk == 0:
            if pk == 0:
                queryset = Orders.objects.all()
            else:
                queryset = Orders.objects.filter(pk=pk)
        else:
            queryset = Orders.objects.filter(waiter = uk)
        serializer = OrdersDetailsSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

#Prośba o wyświetlenie wszystki pozycji z zamówień lub wybranej
class OrdershasDishesView(APIView):
    def get(self, request, pk, ok):
        requier_perms = ['view_orders']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        if ok == 0:
            if pk == 0:
                queryset = OrdersHasDishes.objects.all()
            else:
                queryset = OrdersHasDishes.objects.filter(pk=pk)
        else: 
            queryset = OrdersHasDishes.objects.filter(Order = ok)
            
        serializer = OrdersHasDishesSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

#Prośba o wyświetlenie wszytskich rachunków, lub wybranego
class BillsView(APIView):
    def get(self, request, pk, uk):
        requier_perms = ['view_orders']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        if uk == 0:
            if pk == 0:
                queryset = Bills.objects.all()
            else:
                queryset = Bills.objects.get(pk=pk)
        else:
            queryset = Bills.objects.filter(waiter = uk)
           
        serializer = BillsSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

#Prośba o szczegółowe wyświetlenie wszystkich pozycji zamówień lub wybranego na bazie zamówienia
class KitchenOrdersView(APIView):
    def get(self, request, pk):
        requier_perms = ['view_orders', 'view_ordershasdishes']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        if pk==0:
            queryset = OrdersHasDishes.objects.filter(done=False).filter(
                Q(Order__isnull=False) & Q(Dish__isnull=False) & Q(Variant__isnull=False)
            )
        else:
            queryset = OrdersHasDishes.objects.filter(done=False, Order=pk).filter(
                Q(Order__isnull=False) & Q(Dish__isnull=False) & Q(Variant__isnull=False)
            )
        serializer = PendingOrderDetailsSerializer(queryset, many=True)
        return Response({'Orders': serializer.data})

#Prośba o zmianienie statusu pozycji zamówienia na wykonane 
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

#Prośba o rozpoczęcie nowego zamowienia nowego zamówienia
class KitchenOrderStartView(APIView):
    def post(self, request):
        requier_perms = ['add_orders']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        serializer = OrderStartSerializer(data = request.data)
        if serializer.is_valid():
            table = serializer.validated_data['table']
            waiter = User.objects.get(pk = id)
            order = Orders.objects.create(waiter_id = waiter, table = table)
            order.save()
            latest_order = Orders.objects.filter(waiter=waiter).latest('time')

            print(latest_order.pk)
            response_data = {
                'Order': latest_order.pk
            }

            return Response(response_data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#Prośba o dodanie jednej lub więcej pozycji do zamówienia
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

#Prośba o dodanie permisji do grupy
class AddPermissionToGroup(APIView):
    def post(self, request):
        requier_perms = ['add_permission', 'change_group']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        serializer = PermissionSerializer(data=request.data, partial=True)
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

#Prośba o dodanie nowej permisji do użytkownika
class AddPermissionToUser(APIView):
    def post(self, request):
        requier_perms = ['add_permission', 'change_user']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        serializer = PermissionSerializer(data=request.data, partial=True)
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

#Proba o uuniecie permisji z wybranej grupy
class RemovePermissionFromGroup(APIView):
    def delete(self, request):
        requier_perms = ['delete_permission', 'change_group']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        serializer = PermissionSerializer(data=request.data, partial=True)
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

#Prośba o usunięcie permisji wybranemu użytkownikowi
class RemovePermissionFromUser(APIView):
    def delete(self, request):
        requier_perms = ['delete_permission', 'change_user']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        serializer = PermissionSerializer(data=request.data, partial=True)
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

#prośba o wyświetlenie listy permisji
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

#prośba o wyświetlenie permisji wybranego użytkownika
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

#Prośba o wywietlenie permiji wybranej grupy
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

#Prośba o wyświetlenie powiadomień dla użytkownika 
class NotificationsView(APIView):
    def get(self,request):
        requier_perms = ['view_notifications']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        
        create_notifications()

        NotificationSet = Notifications.objects.filter(To = id).exclude(status = 2)
        if not NotificationSet.exists():
            return Response({'message': 'Brak powiadomień'}, status=status.HTTP_404_NOT_FOUND)
        serializer = NotificationsSerializer(NotificationSet, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

#Prośba o wyświetlenie danych wybranego lub wzystkich użytkowników 
class UserView(APIView):
    def get(self, request, pk):
        requier_perms = ['view_notifications']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        if pk == 0:
            queryset = User.objects.all()
        else:
            queryset = User.objects.get(pk = pk)

        if not queryset:
            raise exceptions.NotFound("Nie znaleziono użytkownika")
        if pk == 0:
            serializer = UserDetailsSerializer(queryset, many = True)
        else:
            serializer = UserDetailsSerializer(queryset, many = False)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
#Prośba o utworzenie nowego powiadomienia
class CreateNotification(APIView):
    def post(self, request):
        requier_perms = ['add_notifications']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        
        serializer = NotificationsSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        response_data = {
            'message': 'Success'
        }
        return Response(response_data, status=status.HTTP_200_OK)

#Proba o zmienienie status powiadomienia na przeczytane
class ViewedNotification(APIView):
    def put(self,request, pk, format=None):
        requier_perms = ['change_notifications']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        try:
            notification = Notifications.objects.get(pk=pk)
        except Notifications.DoesNotExist:
            return Response({'error': 'Notification not found'}, status=status.HTTP_404_NOT_FOUND)
        if  User.objects.get(pk = id) != notification.To:
            raise exceptions.APIException('access denied')

        notification.status = 2
        notification.save()

        serializer = NotificationsSerializer(notification)
        return Response({"message": "success"}, status=status.HTTP_200_OK)
    

class RemoveUser(APIView):
    def delete(self, request, pk):
        requier_perms = ['delete_user']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        user = get_object_or_404(User, pk=pk)

        user.delete()

        return Response({'message': 'Użytkownik został pomyślnie usunięty'}, status=status.HTTP_200_OK)

class DeactivateUser(APIView):
    def patch(self, request, pk):
        requier_perms = ['change_user']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        user = get_object_or_404(User, pk=pk)

        user.is_active = False
        user.fired_time = timezone.now().date()
        user.save()

        return Response({'message': 'Użytkownik został pomyślnie dezaktywowany'}, status=status.HTTP_200_OK)
    
class AddGroupView(APIView):
    def post(self, request):
        requier_perms = ['add_group']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        group_name = request.data.get('group_name')
        
        print(group_name)
        # Sprawdź, czy grupa o takiej nazwie już istnieje
        if Group.objects.filter(name=group_name).exists():
            return Response({'error': 'Grupa o tej nazwie już istnieje'}, status=status.HTTP_400_BAD_REQUEST)

        # Utwórz nową grupę
        new_group = Group.objects.create(name=group_name)
        new_group.save()

        return Response({'message': 'Nowa grupa została pomyślnie utworzona'}, status=status.HTTP_201_CREATED)

class DeleteGroupView(APIView):
    def delete(self, request, pk):
        requier_perms = ['delete_group']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        group = get_object_or_404(Group, pk=pk)

        # Sprawdź, czy grupa nie jest używana przed usunięciem
        if User.objects.filter(groups=group).exists():
            return Response({'error': 'Nie można usunąć grupy, która jest przypisana do użytkowników'}, status=status.HTTP_400_BAD_REQUEST)

        group.delete()

        return Response({'message': 'Grupa została pomyślnie usunięta'}, status=status.HTTP_200_OK)
    
class EditUserView(APIView):
    def patch(self, request, pk):
        require_perms = ['change_user']
        refresh_token = request.COOKIES.get('refreshToken')
        user_id = decode_refresh_token(refresh_token)
        
        if not check_perms(id=user_id, requier_perms=require_perms):
            raise exceptions.APIException('access denied')
        
        user = get_object_or_404(User, pk=pk)
        serializer = UserDetailsSerializer(user, data=request.data, partial=True)
        
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Dane użytkownika zostały pomyślnie zaktualizowane'}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class CreateBill(APIView):
    def post(self, request, pk):
        requier_perms = ['add_bills']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        if Orders.objects.filter(pk = pk).exists() == False:
            return Response({'error': 'Nie ma takiego zamówienia'}, status=status.HTTP_404_NOT_FOUND)
        if OrdersHasDishes.objects.filter(Order = pk).exists() == False:
            return Response({'error': 'To zamówienie nie ma pozycji'}, status=status.HTTP_404_NOT_FOUND)
        total_cost = OrdersHasDishes.objects.filter(Order_id=pk).aggregate(Sum('Dish__Cost'))['Dish__Cost__sum']
        order = Orders.objects.get(Order = pk)
        waiter = User.objects.get(pk = id)
        if Bills.objects.filter(order = order).exists():
            return Response({'error': 'Taki rachunek już istnieje'}, status=status.HTTP_400_BAD_REQUEST)
        bill = Bills.objects.create(order = order, waiter = waiter, Cost = total_cost)
        
        ofbill = Bills.objects.get(order = order)
        serializer = BillsSerializer(ofbill, many = False)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class DeleteOrderPartView(APIView):
    def delete(self, request, pk):
        requier_perms = ['delete_ordershasdishes']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        Order = get_object_or_404(OrdersHasDishes, pk=pk)

        if Order.done == True:
            return Response({'error': 'Nie można usunąć Zamówienia, które zostało już wykonane!'}, status=status.HTTP_400_BAD_REQUEST)
        Order.delete()

        return Response({'message': 'Zamówienie zostało pomyślnie usunięte'}, status=status.HTTP_200_OK)
    
class DeleteOrderView(APIView):
    def delete(self, request, pk):
        requier_perms = ['delete_orders']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        Order = get_object_or_404(Orders, pk = pk)

        if OrdersHasDishes.objects.filter(Order = pk).exists():
            return Response({'error': 'Nie można usunąć zamówienia, które posiada pozycje'}, status=status.HTTP_400_BAD_REQUEST)
        Order.delete()

        return Response({'message': 'Zamówienie zostało pomyślnie usunięte'}, status=status.HTTP_200_OK)
    
class AddDishView(APIView):
    def post(self, request, format=None):
        requier_perms = ['add_dishes']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        serializer = DishesSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            dish = Dishes.objects.get(name = request.data.get('name'))
            serializer2 = DishesSerializer(dish, many = False)
            return Response(serializer2.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class AddCategoryView(APIView):
    def post(self, request, format=None):
        requier_perms = ['add_categories']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        serializer = CategoriesSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            category = Categories.objects.get(name = request.data.get('name'))
            serializer2 = DishesSerializer(category, many = False)
            return Response(serializer2.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class AddDishesProductsView(APIView):
    def post(self, request, format=None):
        requier_perms = ['add_dishesproducts']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        serializer = DishesProductsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class AddDishesVariantsView(APIView):
    def post(self, request, format=None):
        requier_perms = ['add_dishesvariants']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        serializer = DishesVariantsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class DeleteCategoty(APIView):
    def delete(self, request, pk, format=None):
        requier_perms = ['delete_categories']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        queryset = Categories.objects.get(pk=pk)
        queryset.delete()
        return Response({'message':'success'},status=status.HTTP_204_NO_CONTENT)

class DeleteDish(APIView):
    def delete(self, request, pk, format=None):
        requier_perms = ['delete_dishes']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        queryset = Dishes.objects.get(pk=pk)
        queryset.delete()
        return Response({'message':'success'},status=status.HTTP_204_NO_CONTENT)

class DeleteDishesProducts(APIView):
    def delete(self, request, pk, format=None):
        requier_perms = ['delete_dishesproducts']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        queryset = DishesProducts.objects.get(pk=pk)
        queryset.delete()
        return Response({'message':'success'},status=status.HTTP_204_NO_CONTENT)

class DeleteDishesVariants(APIView):
    def delete(self, request, pk, format=None):
        requier_perms = ['delete_dishesvariants']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        queryset = DishesVariants.objects.get(pk=pk)
        queryset.delete()
        return Response({'message':'success'},status=status.HTTP_204_NO_CONTENT)

class UpdateCategoty(APIView):
    def patch(self, request, pk, format=None):
        requier_perms = ['change_categories']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        category = Categories.objects.get(pk=pk)
        serializer = CategoriesSerializer(category, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UpdateDish(APIView):
    def patch(self, request, pk, format=None):
        requier_perms = ['change_dishes']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        dish = Dishes.objects.get(pk=pk)
        serializer = DishesSerializer(dish, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UpdateDishesProducts(APIView):
    def patch(self, request, pk, format=None):
        requier_perms = ['change_dishesproducts']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        dishes_products = DishesProducts.objects.get(pk=pk)
        serializer = DishesProductsSerializer(dishes_products, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UpdateDishesVariants(APIView):
    def patch(self, request, pk, format=None):
        requier_perms = ['change_dishesvariants']
        refresh_token = request.COOKIES.get('refreshToken')
        id = decode_refresh_token(refresh_token)
        if not check_perms(id=id, requier_perms=requier_perms):
            raise exceptions.APIException('access denied')
        dishes_variants = DishesVariants.objects.get(pk=pk)
        serializer = DishesVariantsSerializer(dishes_variants, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class CashOutView(APIView):
    def get(self, request):
        pass