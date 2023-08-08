from django.db import models
from accounts.models import HospitalUser
from baseapp.models import BaseModel
# Create your models here.


class NurseDetail(BaseModel):
    """Nurse model fields"""

    nurse = models.ForeignKey(HospitalUser, on_delete=models.CASCADE, default=None, null=True)
    phone_number = models.IntegerField(null=False)
