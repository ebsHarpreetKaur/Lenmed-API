"""baseapp models"""
from django.db import models


class BaseModel(models.Model):
    """base app model fields"""
    id = models.AutoField(primary_key=True)
    modified_at = models.DateTimeField(verbose_name="Updated", auto_now=True, editable=False)
    created_at = models.DateTimeField(verbose_name="Created", auto_now_add=True, editable=False)

    class Meta:
        abstract = True
