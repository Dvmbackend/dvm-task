from django.db import models
class Bus(models.Model):
    bus_type_choices = [
        ('Standard', 'Standard class'),
        ('Executive', 'Executive class'),
        ('Sleeper', 'Sleeper class')
    ]

    bus_type = models.CharField(max_length=20, choices=bus_type_choices)
    pickup_location = models.CharField(max_length=100)
    destination_location = models.CharField(max_length=100)
    date = models.DateField()
    available_seats = models.IntegerField()

    def __str__(self):
        return f'{self.bus_type} from {self.pickup_location} to {self.destination_location}'
    from django.db import models

class OTP(models.Model):
    email = models.EmailField()
    otp = models.CharField(max_length=6)
    expiry = models.DateTimeField()


    def __str__(self):
        return f"{self.email} - {self.otp}"
class UserEmail(models.Model):
    email = models.EmailField(unique=True) 
    date_added = models.DateTimeField(auto_now_add=True)  
    def __str__(self):
        return self.email
from django.db import models

class UserRegistration(models.Model):
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255)
    confirm_password = models.CharField(max_length=255)

    def __str__(self):
        return self.email
