from django.contrib import admin


from django.contrib import admin
from .models import UserEmail

admin.site.register(UserEmail)
from django.contrib import admin
from .models import UserRegistration

@admin.register(UserRegistration)
class UserRegistrationAdmin(admin.ModelAdmin):
    list_display = ('email', 'password', 'confirm_password')  
