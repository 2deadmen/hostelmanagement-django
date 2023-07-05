# Generated by Django 4.0.3 on 2023-07-05 17:38

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('vmsApp', '0003_users'),
    ]

    operations = [
        migrations.CreateModel(
            name='Users_request',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=250)),
                ('reason', models.CharField(max_length=500)),
                ('location', models.CharField(max_length=500)),
                ('phone', models.CharField(blank=True, max_length=250, null=True)),
                ('date_depart', models.DateTimeField(default=django.utils.timezone.now)),
                ('date_return', models.DateTimeField(default=django.utils.timezone.now)),
                ('state', models.IntegerField(default=0)),
            ],
        ),
        migrations.DeleteModel(
            name='Users',
        ),
    ]
