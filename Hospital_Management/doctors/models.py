from django.db import models
from accounts.models import HospitalUser, Role
from baseapp.models import BaseModel
from hospital.models import Hospital
from django.utils.translation import gettext_lazy as _


class DoctorDetail(BaseModel):
    """Doctor model fields"""

    GENDER_CHOICES = [
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Other', 'Other'),
    ]
    doctor = models.ForeignKey(HospitalUser, on_delete=models.CASCADE, default=None, null=True)
    phone_number = models.IntegerField(null=False)
    gender = models.CharField(max_length=20, choices=GENDER_CHOICES, null=False)
    specialization = models.CharField(max_length=100)


class DoctorsToHospital(BaseModel):
    """ Model to check which doctor is assign to which Admin """
    doctor = models.ForeignKey(DoctorDetail, on_delete=models.CASCADE, default=None, null=True)
    assign_to = models.ForeignKey(Hospital, on_delete=models.CASCADE, default=None, null=True)
