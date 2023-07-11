from rest_framework import serializers
from .models import Hospital


class HospitalSerializer(serializers.ModelSerializer):
    """ Hospital fields to return in response"""
    class Meta:
        model = Hospital
        fields = ('id', 'admin_email', 'name', 'admin', 'address')
