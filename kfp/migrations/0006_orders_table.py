# Generated by Django 4.1.5 on 2024-01-11 16:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('kfp', '0005_alter_ordershasdishes_note'),
    ]

    operations = [
        migrations.AddField(
            model_name='orders',
            name='table',
            field=models.CharField(max_length=4, null=True),
        ),
    ]
