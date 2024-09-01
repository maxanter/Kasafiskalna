import os
from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.utils import timezone

#Zdefiniowanie przestrzeni na media
def images_path(instance, filename):
    return os.path.join(settings.LOCAL_FILE_DIR, 'images', filename)

#Manualna deklaracja modelu Użytkowników
class User(AbstractUser):
    username = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255, null=False)

    hired_time = models.DateField(default=timezone.now)
    fired_time = models.DateField(default=None, null=True)
    phone_no = models.TextField(max_length=13, null=True)


    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []
    groups = models.ManyToManyField(Group, related_name='user_groups')
    user_permissions = models.ManyToManyField(Permission, related_name='user_user_permissions')


#Deklaracja tabel Odpowiadających za kase fiskalną
class Categories(models.Model):
    Category = models.IntegerField(primary_key=True)
    name = models.TextField(max_length=50)
    higher_category = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True)


class Dishes(models.Model):
    D_no = models.IntegerField(primary_key=True)
    name = models.TextField(max_length=50, null=False, unique=True)
    category = models.ForeignKey(Categories, on_delete=models.CASCADE, null=True)
    D_img = models.ImageField(upload_to='DishPng/', null=True)
    description = models.TextField(max_length=500, null=True)
    Cost = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        null=True
    )
    Base_Cost = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        null=True
    )
    vat = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        null=True
    )

class DishesProducts(models.Model):
    Dish = models.ForeignKey(Dishes, on_delete=models.CASCADE, null=False)
    name = models.TextField(max_length=45, null=False)
    weight = models.DecimalField(
        max_digits=8,
        decimal_places=3,
        default=0.000,
        null=True
    )    

class DishesVariants(models.Model):
    Variant_no = models.CharField(max_length=45, null=False)
    Dish = models.ForeignKey(Dishes, on_delete=models.CASCADE, null=False)
    count = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        default=1.00,
        null=False
    )
    Cost = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        null=True
    )

# class DishesStatus(models.Model):
#     class Status(models.IntegerChoices):
#         AVAILABLE = 0, 'Dostepny'
#         NOT_AVAILABLE = 1, 'Niedostepny'
#         OUT_OF_STOCK = 2, 'Brak w magazynie'
#     Dish = models.ForeignKey(Dishes, on_delete=models.CASCADE, null=False)
#     status = models.IntegerField(default=0, choices=Status.choices)
#     note = models.TextField(max_length=500, null=True)

# class DishesNotes(models.Model):
#     Dish = models.ForeignKey(Dishes, on_delete=models.CASCADE, null=False)
#     note = models.TextField(max_length=500, null=True)

class Orders(models.Model):
    Order = models.IntegerField(primary_key=True)
    time = models.DateTimeField(default=timezone.now)
    waiter = models.ForeignKey(User, on_delete=models.CASCADE, null=False)
    table = models.CharField(max_length=4, null=True)

class OrdersHasDishes(models.Model):
    class Done(models.IntegerChoices):
        NOT_ACTIVE = 0, 'Nie aktywne'
        NOT_DONE = 1, 'Nie zrobione'
        DONE = 2, 'Zrobione'
        PAUSED = 3, 'Wstrzymane'

    Order = models.ForeignKey(Orders, on_delete=models.CASCADE, null=False)
    Dish = models.ForeignKey(Dishes, on_delete=models.CASCADE, null=False)
    Variant = models.ForeignKey(DishesVariants, on_delete=models.CASCADE, null=False)
    variant_count = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        default=1.00,
        null=False
    )
    note = models.TextField(max_length = 500, null=True)
    count = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        default=1.00,
        null=False
    )
    done = models.IntegerField(default=0, choices=Done.choices)

class Bills(models.Model):
    Bill = models.IntegerField(primary_key=True)
    order = models.ForeignKey(Orders, on_delete=models.CASCADE, null=False)
    time = models.DateTimeField(default=timezone.now)
    waiter = models.ForeignKey(User, on_delete=models.CASCADE, null=False)
    Cost = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        null=False
    )

class Notifications(models.Model):
    class Status(models.IntegerChoices):
        INFO = 0, 'Info'
        WARNING = 1, 'Warning'
        END = 2, 'End'
    
    Notification_no = models.AutoField(primary_key=True)
    To = models.ForeignKey(User, on_delete=models.CASCADE, null=False)
    notification = models.TextField(max_length=511, null=False)
    status = models.IntegerField(choices=Status.choices)
    Order = models.ForeignKey(Orders,on_delete=models.CASCADE, null=True)

