from rest_framework import serializers
from .models import HospitalUser, Role, Permission


class GetCurrentUserSerializer(serializers.ModelSerializer):
    """ User fields to return in response"""
    class Meta:
        model = HospitalUser
        fields = ('id', 'email', 'name', 'role_detail')


class HospitalUserSerializer(serializers.ModelSerializer):
    """ Serializer to add/update user """
    class Meta:
        model = HospitalUser
        fields = ('email', 'name', 'role', 'password', 'is_admin')


class RoleSerializer(serializers.ModelSerializer):
    """ Serializer to handle Role """
    class Meta:
        model = Role
        fields = ('id', 'role', 'permission')


class PermissionSerializer(serializers.ModelSerializer):
    """ Serializer to handle Role """
    class Meta:
        model = Permission
        fields = ('id',  'name', 'permission_key')
