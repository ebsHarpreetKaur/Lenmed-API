from rest_framework import serializers
from .models import DoctorDetail, DoctorsToHospital


class DoctorSerializer(serializers.ModelSerializer):
    """Handle Doctor's fields to return in response"""
    class Meta:
        model = DoctorDetail
        fields = ('id', 'doctor', 'phone_number',
                  'gender', 'specialization')


class DoctorsToHospitalSerializer(serializers.ModelSerializer):
    """ Handle DoctorsToHospital fields """
    class Meta:
        model = DoctorsToHospital
        fields = ('id', 'doctor', 'assign_to')
