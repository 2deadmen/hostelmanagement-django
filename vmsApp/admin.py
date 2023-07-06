from django.contrib import admin
from vmsApp import models

# Register your models here.
admin.site.register(models.Departments)
admin.site.register(models.Visitors)
admin.site.register(models.Users_request)
admin.site.register(models.Users)

