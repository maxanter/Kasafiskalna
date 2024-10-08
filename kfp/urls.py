from django.urls import path
from .views import (RegisterLoginAPIView, UserAPIView, CategoriesView, 
                    DishesView, DishesProductsView, DishesVariantsView, 
                    OrdersDetailsView, BillsView, OrdershasDishesView, 
                    KitchenOrdersView, GroupView, UserView, GroupPermisionsView, 
                    UserPermissionsView, PermissionsView, UserGroupView, NotificationsView)
urlpatterns = [
    path('register', RegisterLoginAPIView.as_view()),
    path('login', RegisterLoginAPIView.as_view()),
    path('logout', RegisterLoginAPIView.as_view()),
    path('user', UserAPIView.as_view()),
    path('Categories/<int:pk>/<int:hk>/', CategoriesView.as_view()),
    path('AddCategory', CategoriesView.as_view()),
    path('DeleteCategory/<int:pk>/', CategoriesView.as_view()),
    path('UpdateCategory/<int:pk>/', CategoriesView.as_view()),
    path('Dishes/<int:pk>/<int:kk>/', DishesView.as_view()),
    path('AddDish', DishesView.as_view()),
    path('DeleteDish/<int:pk>/', DishesView.as_view()),
    path('UpdateDish/<int:pk>/', DishesView.as_view()),
    path('DishesProducts/<int:pk>/<int:dk>/', DishesProductsView.as_view()),
    path('AddDishesProducts', DishesProductsView.as_view()),
    path('DeleteDishesProducts/<int:pk>/', DishesProductsView.as_view()),
    path('UpdateDishesProducts/<int:pk>/', DishesProductsView.as_view()),
    path('DishesVariants/<int:pk>/<int:dk>/', DishesVariantsView.as_view()),
    path('AddDishesVariants', DishesVariantsView.as_view()),
    path('DeleteDishesVariants/<int:pk>/', DishesVariantsView.as_view()),
    path('UpdateDishesVariants/<int:pk>/', DishesVariantsView.as_view()),
    path('OrdersDetails/<int:pk>/<int:uk>/', OrdersDetailsView.as_view()),
    path('DeleteOrder/<int:pk>/', OrdersDetailsView.as_view()),    
    path('Bills/<int:pk>/<int:uk>/', BillsView.as_view()),
    path('CreateBill/<int:pk>/', BillsView.as_view()),
    path('OrdershasDishes/<int:pk>/<int:ok>/', OrdershasDishesView.as_view()),
    path('DeleteOrderPart/<int:pk>/', OrdershasDishesView.as_view()),    
    path('KitchenOrders/<int:pk>/', KitchenOrdersView.as_view()),
    path('UpdateDoneStatus/<int:pk>/', KitchenOrdersView.as_view()),
    path('KitchenOrderStart', KitchenOrdersView.as_view()),
    path('KitchenOrderCreate', KitchenOrdersView.as_view()),
    path('Groups/<int:pk>/<int:uk>/', GroupView.as_view()),
    path('AddGroup', GroupView.as_view()),
    path('DeleteGroup/<int:pk>/', GroupView.as_view()),
    path('Users/<int:pk>/<int:gk>/', UserView.as_view()),
    path('EditUser/<int:pk>/', UserView.as_view()),
    path('RemoveUser/<int:pk>/', UserView.as_view()),
    path('DeactivateUser/<int:pk>/', UserView.as_view()),
    path('AddPermissionToGroup', GroupPermisionsView.as_view()),
    path('RemovePermissionFromGroup', GroupPermisionsView.as_view()),
    path('GroupPermissions/<int:pk>/<str:perm>/', GroupPermisionsView.as_view()),
    path('AddPermissionToUser', UserPermissionsView.as_view()),
    path('UserPermissions/<int:pk>/<str:perm>/', UserPermissionsView.as_view()),
    path('RemovePermissionFromUser', UserPermissionsView.as_view()),
    path('Permissions', PermissionsView.as_view()),
    path('UserGroup/<int:pk>/<str:is_member>/', UserGroupView.as_view()),
    path('AddUserToGroup/<int:uk>/<int:gk>/', UserGroupView.as_view()),
    path('RemoveUserFromGroup/<int:uk>/<int:gk>/', UserGroupView.as_view()),
    path('Notifications', NotificationsView.as_view()),
    path('ViewedNotification/<int:pk>/', NotificationsView.as_view()),
    path('CheckNotifications', NotificationsView.as_view()),
    path('CreateNotification', NotificationsView.as_view()),    
]