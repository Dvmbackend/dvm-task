from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import UserEmail

# Register the UserEmail model with the Django admin
admin.site.register(UserEmail)
from django.contrib import admin
from .models import UserRegistration

@admin.register(UserRegistration)
class UserRegistrationAdmin(admin.ModelAdmin):
    list_display = ('email', 'password', 'confirm_password')  # Customize based on your needs
