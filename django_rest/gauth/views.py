from django.shortcuts import render
from django.http import JsonResponse,HttpResponse,HttpResponseRedirect
from django.shortcuts import render,redirect  
from django.contrib.auth.forms import UserCreationForm  
from django.contrib.auth import authenticate,login,logout
from django.contrib import messages
from rest_framework import views, permissions
from rest_framework.response import Response
from rest_framework import status
from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice
from .utils import send_otp
import pyotp
from datetime import datetime,timedelta
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User 

      
# Create your views here.
def hello(request):
    is_auth="no"
    if(request.user.is_authenticated):
        is_auth="yes"
    return JsonResponse({"message":is_auth})


def user_register(request):  
    form = UserCreationForm()  
    if request.POST == 'POST':  
        if form.is_valid():  
            form.save()  
            redirect('login')
    messages.success(request, 'Account created successfully')  
    
    context = {  
        'form':form  
    }  
    print(context)
    return render(request, 'gauth/register.html', context)



def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user:
            if user.is_active:
                #login(request,user)
                send_otp(request)
                request.session['username']=username
                return redirect('otp')
            else:
                return JsonResponse("Your account was inactive.")
        else:
            print("Someone tried to login and failed.")
            #print("They used username: {} and password: {}".format(username,password))
            return JsonResponse("Invalid login details given")
    else:
        return render(request, 'gauth/login.html')
    

'''def register(request):
    registered = False
    if request.method == 'POST':
        user_form = UserForm(data=request.POST)
        profile_form = UserProfileInfoForm(data=request.POST)
        if user_form.is_valid() and profile_form.is_valid():
            user = user_form.save()
            user.set_password(user.password)
            user.save()
            profile = profile_form.save(commit=False)
            profile.user = user
            if 'profile_pic' in request.FILES:
                print('found it')
                profile.profile_pic = request.FILES['profile_pic']
            profile.save()
            registered = True
        else:
            print(user_form.errors,profile_form.errors)
    else:
        user_form = UserForm()
        profile_form = UserProfileInfoForm()
    return render(request,'dappx/registration.html',
                          {'user_form':user_form,
                           'profile_form':profile_form,
                           'registered':registered})'''

def user_logout(request):
    logout(request)
    redirect('/')

def otp_view(request):
    error_message=None
    if request.method== 'POST':
        otp=request.session['otp']
        username=request.session['username']
        otp_secret_key=request.session['otp_secret_key']
        otp_valid_until=request.session['otp_valid_date']

        if otp_secret_key and otp_valid_until is not None:
            valid_until=datetime.fromisofformat(otp_valid_until)
            if valid_until > datetime.now():
                totp=pyotp.TOTP(otp_secret_key,interval=60)
                if totp.verify(otp):
                    user=get_object_or_404(User,username=username)
                    login(request,user)
                    del request.session['otp_secret_key']
                    del request.session['otp_valid_date']
                    return redirect('')
                else:
                    error_message='invalid OTP'
            else:
                error_message='Password has expired'
        else:
            error_message='invalid OTP'
    return render(request,'otp.html',{"error":error_message})


'''def get_user_totp_device(self, user, confirmed=None):
    devices = devices_for_user(user, confirmed=confirmed)
    for device in devices:
        if isinstance(device, TOTPDevice):
            return device 
        
class TOTPCreateView(views.APIView):
    """
    Use this endpoint to set up a new TOTP device
    """
    permission_classes = [permissions.IsAuthenticated]    
    def get(self, request, format=None):
        user = request.user
        device = get_user_totp_device(self, user)
        if not device:
            device = user.totpdevice_set.create(confirmed=False)
        url = device.config_url
        return Response(url, status=status.HTTP_201_CREATED)
class TOTPVerifyView(views.APIView):
    """
    Use this endpoint to verify/enable a TOTP device
    """
    permission_classes = [permissions.IsAuthenticated]    
    def post(self, request, token, format=None):
        user = request.user
        device = get_user_totp_device(self, user)
        if not device == None and device.verify_token(token):
            if not device.confirmed:
                device.confirmed = True
                device.save()
            return Response(True, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_400_BAD_REQUEST)'''