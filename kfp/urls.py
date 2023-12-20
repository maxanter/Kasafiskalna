from django.urls import path
from .views import CategoriesView, RegisterAPIView, LoginAPIView, UserAPIView, \
    RefreshApiView, LogoutApiView, DishesView, DishesProductsView, DishesVariantsView, OrdersDetailsView, \
    BillsView, KitchenOrdersView, UpdateDoneStatusAPIView, KitchenOrderCreateView, OrdershasDishesView, KitchenOrderStartView, \
    AddPermissionToGroup, AddPermissionToUser, RemovePermissionFromGroup, RemovePermissionFromUser, PermissionsView, \
    UserPermissionsView, GroupPermissionsView

urlpatterns = [
    path('register', RegisterAPIView.as_view()),
    path('login', LoginAPIView.as_view()),
    path('user', UserAPIView.as_view()),
    path('refresh', RefreshApiView.as_view()),
    path('logout', LogoutApiView.as_view()),
    path('Categories', CategoriesView.as_view()),
    path('Dishes', DishesView.as_view()),
    path('DishesProducts', DishesProductsView.as_view()),
    path('DishesVariants', DishesVariantsView.as_view()),
    path('OrdersDetails', OrdersDetailsView.as_view()),
    path('Bills', BillsView.as_view()),
    path('OrdershasDishes', OrdershasDishesView.as_view()),
    path('KitchenOrders', KitchenOrdersView.as_view()),
    path('UpdateDoneStatus/<int:pk>/', UpdateDoneStatusAPIView.as_view()),
    path('KitchenOrderStart', KitchenOrderStartView.as_view()),
    path('KitchenOrderCreate', KitchenOrderCreateView.as_view()),
    path('AddPermissionToGroup', AddPermissionToGroup.as_view()),
    path('AddPermissionToUser', AddPermissionToUser.as_view()),
    path('RemovePermissionFromGroup', RemovePermissionFromGroup.as_view()),
    path('RemovePermissionFromUser', RemovePermissionFromUser.as_view()),
    path('Permissions', PermissionsView.as_view()),
    path('UserPermissions/<int:pk>/', UserPermissionsView.as_view()),
    path('GroupPermissions/<int:pk>/', GroupPermissionsView.as_view()),
]