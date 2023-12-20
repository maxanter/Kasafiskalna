from django.db.models.signals import post_migrate
from django.dispatch import receiver
from .models import User, Categories, Dishes, DishesProducts, DishesVariants, Orders, OrdersHasDishes, Bills, Notifications

@receiver(post_migrate)
def fill_initial_data(sender, **kwargs):
    if kwargs.get('app', None) == 'kfp':
        Category1 = Categories.objects.create(name = 'Dania')
        Category2 = Categories.objects.create(name = 'Dania główne', higher_category=Category1)
        Category3 = Categories.objects.create(name = 'Zupy', higher_category=Category1)
        Dish1 = Dishes.objects.create(name = 'Schabowy', category = Category2)
        Dish2 = Dishes.objects.create(name = 'Pomidorowa', category = Category3)
        Product11 = DishesProducts.objects.create(Dish = Dish1, name = 'shab', weight = 0.300)
        Product12 = DishesProducts.objects.create(Dish = Dish1, name = 'Kolesław', weight = 0.150)
        Product21 = DishesProducts.objects.create(Dish = Dish2, name = 'marchew', weight = 0.050)
        Product22 = DishesProducts.objects.create(Dish = Dish2, name = 'wywar pomidorowy', weight = 0.300)
        Variant11 = DishesVariants.objects.create(Variant_no = 'Ziemniaki gotowane', Dish = Dish1, count = 0.250)
        Variant12 = DishesVariants.objects.create(Variant_no = 'Frytki', Dish = Dish1, count = 0.210)
        Variant21 = DishesVariants.objects.create(Variant_no = 'Makaron', Dish = Dish1, count = 0.250)
        Variant22 = DishesVariants.objects.create(Variant_no = 'Ryż', Dish = Dish1, count = 0.250)
        Order1 = Orders.objects.create(waiter = 1)
        Order2 = Orders.objects.create(waiter = 1)
        Order11 = OrdersHasDishes.objects.create(Order = Order1, Dish = Dish1, Variant = Variant11, done = True)
        Order12 = OrdersHasDishes.objects.create(Order = Order1, Dish = Dish2, Variant = Variant21, done = True)
        Order11 = OrdersHasDishes.objects.create(Order = Order2, Dish = Dish2, Variant = Variant22)
        Order11 = OrdersHasDishes.objects.create(Order = Order2, Dish = Dish1, Variant = Variant12)
        Bill1 = Bills.objects.create(order = Order1, waiter = 1, Cost = 10.00)
        Notification1 = Notifications.objects.create(To = 1, notification = 'Test 1', status = 0)
        Notification1 = Notifications.objects.create(To = 1, notification = 'Test 2', status = 2)