from django.urls import path
from .views import AddCategoryView, AddDishView, AddDishesProductsView, AddDishesVariantsView, AddGroupView, AddUserToGroup, CategoriesView, CreateBill, CreateNotification, DeactivateUser, DeleteCategoty, DeleteDish, DeleteDishesProducts, DeleteDishesVariants, DeleteGroupView, DeleteOrderPartView, DeleteOrderView, EditUserView, GroupView, NotificationsView,  RegisterAPIView, LoginAPIView, RemoveUser, RemoveUserFromGroup, UpdateCategoty, UpdateDish, UpdateDishesProducts, UpdateDishesVariants, UserAPIView, \
    RefreshApiView, LogoutApiView, DishesView, DishesProductsView, DishesVariantsView, OrdersDetailsView, \
    BillsView, KitchenOrdersView, UpdateDoneStatusAPIView, KitchenOrderCreateView, OrdershasDishesView, KitchenOrderStartView, \
    AddPermissionToGroup, AddPermissionToUser, RemovePermissionFromGroup, RemovePermissionFromUser, PermissionsView, \
    UserPermissionsView, GroupPermissionsView, UserView, ViewedNotification

urlpatterns = [
    path('register', RegisterAPIView.as_view()),
    path('login', LoginAPIView.as_view()),
    path('user', UserAPIView.as_view()),
    path('refresh', RefreshApiView.as_view()),
    path('logout', LogoutApiView.as_view()),
    path('Categories/<int:pk>/<int:hk>/', CategoriesView.as_view()),
    path('Dishes/<int:pk>/<int:kk>/', DishesView.as_view()),
    path('DishesProducts/<int:pk>/<int:dk>/', DishesProductsView.as_view()),
    path('DishesVariants/<int:pk>/<int:dk>/', DishesVariantsView.as_view()),
    path('OrdersDetails/<int:pk>/<int:uk>/', OrdersDetailsView.as_view()),
    path('Bills/<int:pk>/<int:uk>/', BillsView.as_view()),
    path('OrdershasDishes/<int:pk>/<int:ok>/', OrdershasDishesView.as_view()),
    path('KitchenOrders/<int:pk>/', KitchenOrdersView.as_view()),
    path('UpdateDoneStatus/<int:pk>/', UpdateDoneStatusAPIView.as_view()),
    path('KitchenOrderStart', KitchenOrderStartView.as_view()),
    path('KitchenOrderCreate', KitchenOrderCreateView.as_view()),
    path('AddPermissionToGroup', AddPermissionToGroup.as_view()),
    path('AddPermissionToUser', AddPermissionToUser.as_view()),
    path('RemovePermissionFromGroup', RemovePermissionFromGroup.as_view()),
    path('RemovePermissionFromUser', RemovePermissionFromUser.as_view()),
    path('Permissions', PermissionsView.as_view()),
    path('UserPermissions/<int:pk>/<str:perm>/', UserPermissionsView.as_view()),
    path('GroupPermissions/<int:pk>/<str:perm>/', GroupPermissionsView.as_view()),
    path('Notifications', NotificationsView.as_view()),
    path('Users/<int:pk>/<int:gk>/', UserView.as_view()),
    path('Groups/<int:pk>/<int:uk>/', GroupView.as_view()),
    path('CreateNotification', CreateNotification.as_view()),
    path('ViewedNotification/<int:pk>/', ViewedNotification.as_view()),
    path('RemoveUser/<int:pk>/', RemoveUser.as_view()),
    path('AddUserToGroup/<int:uk>/<int:gk>/', AddUserToGroup.as_view()),
    path('RemoveUserFromGroup/<int:uk>/<int:gk>/', RemoveUserFromGroup.as_view()),
    path('DeactivateUser/<int:pk>/', DeactivateUser.as_view()),
    path('AddGroup', AddGroupView.as_view()),
    path('DeleteGroup/<int:pk>/', DeleteGroupView.as_view()),
    path('EditUser/<int:pk>/', EditUserView.as_view()),
    path('CreateBill/<int:pk>/', CreateBill.as_view()),
    path('DeleteOrder/<int:pk>/', DeleteOrderView.as_view()),
    path('DeleteOrderPart/<int:pk>/', DeleteOrderPartView.as_view()),
    path('AddDish', AddDishView.as_view()),
    path('AddCategory', AddCategoryView.as_view()),
    path('AddDishesProducts', AddDishesProductsView.as_view()),
    path('AddDishesVariants', AddDishesVariantsView.as_view()),
    path('DeleteDish/<int:pk>/', DeleteDish.as_view()),
    path('DeleteCategory/<int:pk>/', DeleteCategoty.as_view()),
    path('DeleteDishesProducts/<int:pk>/', DeleteDishesProducts.as_view()),
    path('DeleteDishesVariants/<int:pk>/', DeleteDishesVariants.as_view()),
    path('UpdateDish/<int:pk>/', UpdateDish.as_view()),
    path('UpdateCategory/<int:pk>/', UpdateCategoty.as_view()),
    path('UpdateDishesProducts/<int:pk>/', UpdateDishesProducts.as_view()),
    path('UpdateDishesVariants/<int:pk>/', UpdateDishesVariants.as_view()),
]