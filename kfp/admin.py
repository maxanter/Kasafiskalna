from django.contrib import admin
from .models import User, Categories, Dishes, DishesProducts, DishesVariants, Orders, OrdersHasDishes, Bills, Notifications

# Register your models here.
admin.site.register(User)
admin.site.register(Categories)
admin.site.register(Dishes)
admin.site.register(DishesProducts)
admin.site.register(DishesVariants)
admin.site.register(Orders)
admin.site.register(OrdersHasDishes)
admin.site.register(Bills)
admin.site.register(Notifications)