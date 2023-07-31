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
    # name = models.CharField(max_length=60, null=False)
    phone_number = models.IntegerField(null=False)
    gender = models.CharField(max_length=20, choices=GENDER_CHOICES, null=False)
    specialization = models.CharField(max_length=100)
    # hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE)
    # role = models.ForeignKey(Role, on_delete=models.CASCADE)
    # email = models.EmailField(_('email'), unique=True, null=False)

    # def __str__(self):
    #     return self.name


# s
