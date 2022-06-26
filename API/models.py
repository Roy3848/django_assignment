from API.manager import EmployeeManager
from django.db import models
from django.contrib.auth.models import AbstractBaseUser

class EmployeeUser(AbstractBaseUser):
    employee_role = {
        ('Engineer','Engineer'),
        ('Associate Engineer','Associate Engineer'),
        ('Trainee Engineer','Trainee Engineer')
    }
    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        unique=True,
    )
    name = models.CharField(max_length=50)
    designtions = models.CharField(max_length=30,choices=employee_role,default="Emplyee")
    phone_no = models.CharField(max_length=20,null=False,blank=False)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_manager = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    objects = EmployeeManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name','phone_no']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        
        return self.is_admin