# Generated by Django 4.1.5 on 2024-02-28 12:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('kfp', '0008_alter_notifications_notification_no'),
    ]

    operations = [
        migrations.AddField(
            model_name='dishes',
            name='vat',
            field=models.DecimalField(decimal_places=2, max_digits=3, null=True),
        ),
    ]
