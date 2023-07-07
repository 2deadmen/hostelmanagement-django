# Generated by Django 4.2.3 on 2023-07-06 18:01

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vmsApp', '0008_alter_users_add'),
    ]

    operations = [
        migrations.AddField(
            model_name='users',
            name='dob',
            field=models.DateTimeField(default=datetime.datetime.now),
        ),
        migrations.AlterField(
            model_name='users_request',
            name='state',
            field=models.CharField(default='Pending', max_length=200),
        ),
    ]
