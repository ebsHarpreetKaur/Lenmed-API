from django.contrib import admin

from django.contrib.auth.models import Group
from .models import HospitalUser, Role, Permission


class UserAdmin(admin.ModelAdmin):
    """ User model's admin"""
    exclude = ('is_staff', 'is_admin', 'is_superuser')

    list_display = ["id", "email", "name"]


class RoleAdmin(admin.ModelAdmin):
    """ Role model's admin"""
    list_display = ["id", "role"]


class PermissionAdmin(admin.ModelAdmin):
    """ Permission model's admin"""
    list_display = ["id", "name"]


admin.site.register(HospitalUser, UserAdmin)
admin.site.register(Role, RoleAdmin)
admin.site.register(Permission, PermissionAdmin)
