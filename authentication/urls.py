from django.urls import path
from .views import *

urlpatterns = [
    path('',home),
    path('auth/register',RegistrationView.as_view(),name='register'),
    path('auth/login',LoginView.as_view(),name='login'),
]
