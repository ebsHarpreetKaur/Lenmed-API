from django.db import models
from baseapp.models import BaseModel
from django.contrib.auth.models import AbstractBaseUser, UserManager
from django.utils.translation import gettext_lazy as _


class Permission(BaseModel):
    # PERMISSION_CHOICES = (
    #     ("View ", "View "),
    #     ("Add ", "Add "),
    #     ("Delete ", "Delete "),
    #     ("Upload ", "Upload "),
    # )
    # name = models.CharField(max_length=100, choices=PERMISSION_CHOICES, null=False, unique=True)
    name = models.CharField(max_length=100, null=False, unique=True)
    permission_key = models.CharField(max_length=50, null=True, unique=True, default=None)
    descrition = models.TextField(null=True, default=None, blank=True)

    class Meta:
        verbose_name_plural = 'Permission'

    def __str__(self):
        return self.name


class Role(BaseModel):
    """Role fields"""

    # ROLE_CHOICES = (
    #     ("Superadmin", "Superadmin"),
    #     ("Admin", "Admin"),

    # )

    role = models.CharField(max_length=50,  null=False, unique=True)
    # role = models.CharField(max_length=50, choices=ROLE_CHOICES, null=False, unique=True)
    permission = models.ManyToManyField(Permission)

    class Meta:
        verbose_name_plural = 'Roles'

    def __str__(self):
        return self.role


class HospitalUser(BaseModel, AbstractBaseUser):
    """HospitalUser User model fields"""

    email = models.EmailField(_('email'), unique=True)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    name = models.CharField(max_length=255, null=False)
    is_admin = models.BooleanField(default=False, db_index=True)
    is_superuser = models.BooleanField(default=False, db_index=True)
    is_active = models.BooleanField(default=True, null=True)
    is_staff = models.BooleanField(default=True, null=True)
    profile_image = models.TextField(blank=True, null=True)
    age = models.IntegerField(null=True)
    blood_group = models.CharField(max_length=15, null=True)

    USERNAME_FIELD = 'email'
    objects = UserManager()

    @property
    def role_detail(self):
        """method to get role details"""
        role = {
            'id': self.role.id,
            'role': self.role.role,
        }
        return role

    def has_module_perms(self, app_label):
        """Does the user have permissions to view the app `app_label`?"""
        # Simplest possible answer: Yes, always
        return True

    def has_perm(self, perm, obj=None):
        """Does the user have a specific permission?"""
        # Simplest possible answer: Yes, always
        return True

    def __str__(self):
        return self.email


class PasswordRecovery(BaseModel):
    """password recovery model's fields"""
    user = models.ForeignKey(HospitalUser, on_delete=models.CASCADE)
    email = models.EmailField(null=False)
    otp = models.CharField(max_length=6, null=False)

    class Meta:
        verbose_name_plural = 'PasswordRecovery'
