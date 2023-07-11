from django.db import models
from baseapp.models import BaseModel
from django.utils.translation import gettext_lazy as _
from accounts.models import HospitalUser
# Create your models here.


class Hospital(BaseModel):

    """Hospital model fields"""
    admin = models.ForeignKey(HospitalUser, on_delete=models.CASCADE)
    admin_email = models.EmailField(_('email'), unique=True)
    name = models.CharField(max_length=255, null=False)
    address = models.TextField(null=False)
