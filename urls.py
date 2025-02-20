from django.urls import path, include
from . import views
from django.contrib import admin
from django.urls import path
from .views import send_otp
from .views import verify_otp
urlpatterns=[
    path('login/',views.login,name='login_page'),
    path('register/',views.register,name='register_page'),
    path('profile/',views.profile,name='profile_page'),
    path('recover/',views.recover,name='recover_page'),
    path('booking/',views.booking,name='booking_page'),
    path('profile/', views.profile, name='profile'),
    path('success/', views.success, name='success'),
    path('user/', views.user, name='user'),
    path('user/', views.verify_otp, name='verify_otp_page'),
    path('recover/', views.recover_password, name='recover_password'),
    path('verify_otp/', views.verify_otp, name='verify_otp'),
    path('reset_password/', views.reset_password, name='reset_password'),
    path('register/', views.register, name='register'),
    path('register/', send_otp, name='register'),
    path('logout/', views.user_logout, name='logout'),

    # Add any other URL paths like 'verify_otp', etc.
]


