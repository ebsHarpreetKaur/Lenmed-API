from rest_framework import serializers
from .models import Doctor


class DoctorSerializer(serializers.ModelSerializer):
    """ Doctor fields to return in response"""
    class Meta:
        model = Doctor
        fields = ('id', 'admin', 'name', 'phone_number',
                  'gender', 'specialization', 'hospital', 'role', 'email')
