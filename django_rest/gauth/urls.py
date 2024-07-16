from django.contrib import admin
from django.urls import path,include,re_path
from .views import hello,user_register,user_login,user_logout,otp_view

urlpatterns = [
    path('', hello,name='home'),
    path('register/', user_register,name='register'),
    path('login/',user_login,name='login'),
    path('logout/',user_logout,name='logout'),
    path('otp/',otp_view,name='otp')
    #re_path(r'^totp/create/$', TOTPCreateView.as_view(), name='totp-create'),
    #re_path(r'^totp/login/(?P<token>[0-9]{6})/$', TOTPVerifyView.as_view(), name='totp-login'),
]
