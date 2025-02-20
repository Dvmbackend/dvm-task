from django.shortcuts import render,redirect
from django.http import HttpResponse




def login(request):
    context ={
        "variable":"this is sent"
    }
    return render(request,'homepage/login.html', context)
    
# Create your views here.
def register(request):
    return render(request,'homepage/register.html')

def profile(request):
    return render(request,'homepage/profile.html')
def user(request):
    return render(request,'homepage/user.html')
def recover(request):
    return render(request,'homepage/recover.html')
def booking(request):
    return render(request,'homepage/booking.html')
def search(request):
    return render(request,'homepage/search.html')

def success(request):
    if request.method == 'POST':
        # Get form data from the user
        pickup_location = request.POST.get('pickup-location')
        destination_location = request.POST.get('destination-location')
        booking_date = request.POST.get('booking-date')
        bus_option = request.POST.get('option')

        # Query available buses based on the user's input
        

        return render(request, 'homepage/success.html')

    return render(request, 'homepage/success.html')
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.contrib import messages
from django.utils.crypto import get_random_string
from django.http import HttpResponse
from .models import OTP
import datetime

# View for the recover password page
def recover_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        # Generate OTP
        otp = get_random_string(length=6, allowed_chars='1234567890')
        otp_expiry = datetime.datetime.now() + datetime.timedelta(minutes=10)  # OTP expires in 10 minutes

        # Save OTP in database (you need to create the OTP model)
        OTP.objects.create(email=email, otp=otp, expiry=otp_expiry)

        # Send OTP to the user's email
        send_mail(
            'Password Recovery OTP',
            f'Your OTP for password recovery is: {otp}',
            'from@example.com',  # Your email address
            [email],  # Recipient email
            fail_silently=False,
        )

        # Notify the user to check their email
        messages.success(request, "An OTP has been sent to your email. Please check it.")

        return redirect('verify_otp')  # Redirect to OTP verification page

    return render(request, 'recover.html')

# View for verifying OTP
def verify_otp(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        otp = request.POST.get('otp')

        if not email or not otp:
            messages.error(request, "Please enter both email and OTP.")
            return render(request, 'verify_otp.html')

        # Check if OTP exists and is valid
        try:
            otp_record = OTP.objects.get(email=email, otp=otp)

            if otp_record.expiry > datetime.datetime.now():  # Check if OTP has expired
                messages.success(request, "OTP Verified! You can now reset your password.")
                return redirect('reset_password')  # Redirect to reset password page
            else:
                messages.error(request, "OTP has expired. Please request a new OTP.")
        except OTP.DoesNotExist:
            messages.error(request, "Invalid OTP. Please try again.")

    return render(request, 'verify_otp.html')


# View for resetting the password
def reset_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        new_password = request.POST.get('new_password')
        
        # You can update the user's password here
        # For example, if you're using Django's User model:
        # user = User.objects.get(email=email)
        # user.set_password(new_password)
        # user.save()

        messages.success(request, "Your password has been reset successfully.")
        return redirect('login')

    return render(request, 'reset_password.html')
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import UserEmail
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
import datetime
from django.core.exceptions import ImproperlyConfigured
def register(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        
        # Save the email to the database
        user_email = UserEmail(email=email)
        user_email.save()

        # Notify the user that the email has been saved
        messages.success(request, 'Your email has been registered. An OTP has been sent to your email.')

        # Generate OTP and send email logic
        otp = get_random_string(length=6, allowed_chars='1234567890')
        otp_expiry = datetime.datetime.now() + datetime.timedelta(minutes=10)  # OTP expires in 10 minutes

        # Send OTP to the user's email
        send_mail(
            'Password Recovery OTP',
            f'Your OTP for password recovery is: {otp}',
            'Harsh.coc.op@gmail.com',  # Your email address
            [email],  # Recipient email
            fail_silently=False,
        )
        
        # Redirect to OTP verification page
        return redirect('verify_otp')
    return render(request, 'homepage/register.html')
def register(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        
        # Add a try/except block around the email sending
        try:
            # Assuming you're sending an email after registration
            send_mail(
                'Subject here',
                '123456.',
                'harsh.coc.op@gmail.com',
                [email],
                fail_silently=False,  # Set to True to suppress errors
            )
        except ImproperlyConfigured as e:
            print(f"Email error: {e}")
            messages.error(request, "There was an error sending the email. Please try again later.")
            return redirect('register')

        return redirect('success')  # After email is sent, redirect to success page
    return render(request, 'homepage/register.html')
import random
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils.crypto import get_random_string
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.decorators import login_required
def send_otp(request):
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        # Ensure passwords match
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('register')  # Replace with your view name

        # Generate OTP
        otp = get_random_string(length=6, allowed_chars='0123456789')

        # Send OTP to email
        subject = "Your OTP Code"
        message = f"Your OTP code is {otp}."
        from_email = settings.EMAIL_HOST_USER

        try:
            send_mail(subject, message, from_email, [email])
            messages.success(request, "OTP sent to your email.")
            return redirect('otp verification')  # Redirect to OTP verification page
        except Exception as e:
            messages.error(request, "Failed to send OTP. Please try again.")
            return redirect('register')

    return render(request, 'http://127.0.0.1:8000/homepage/register/')
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import UserRegistration
from django.contrib.auth.hashers import make_password  # For password hashing

def register(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        # Check if passwords match
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'register.html')

        # Check if email already exists
        if UserRegistration.objects.filter(email=email).exists():
            messages.error(request, "Email is already registered.")
            return render(request, 'register.html')

        # Hash the password before saving
        hashed_password = make_password(password)

        # Save to the UserRegistration model
        user = UserRegistration.objects.create(
            email=email,
            password=hashed_password,
            confirm_password=make_password(confirm_password)  # Hashing confirm password as well
        )

        # Optionally, send OTP here (this part depends on your OTP implementation)

        messages.success(request, "Registration successful. You can now verify your OTP.")
        return redirect('verify_otp')  # Adjust based on your URL configuration

    return render(request, 'register.html')
def user_login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Authenticate the user
        user = authenticate(request, username=email, password=password)

        if user is not None:
            # Log the user in
            login(request, user)
            return redirect(href='http://127.0.0.1:8000/homepage/profile/')  # Redirect to the profile page after login
        else:
            messages.error(request, 'Invalid email or password.')

    return render(request, 'http://127.0.0.1:8000/homepage/user/')
def user_profile(request):
    return render(request, 'http://127.0.0.1:8000/homepage/profile/')
from django.contrib.auth import logout
from django.shortcuts import redirect

def user_logout(request):
    logout(request)
    return redirect(href='http://127.0.0.1:8000/homepage/login/')  # Redirect to login page after logging out
