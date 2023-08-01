from rest_framework import serializers
from .models import DoctorDetail


class DoctorSerializer(serializers.ModelSerializer):
    """ Doctor fields to return in response"""
    class Meta:
        model = DoctorDetail
        fields = ('id', 'doctor', 'phone_number',
                  'gender', 'specialization')
