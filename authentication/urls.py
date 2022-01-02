from django.urls import path
from .views import HomeView,RegistrationView,LoginView,ActivateAccountView,LogoutView
from django.contrib.auth.decorators import login_required

urlpatterns = [
    path('',login_required(HomeView.as_view()),name='home'),
    path('auth/register',RegistrationView.as_view(),name='register'),
    path('auth/login',LoginView.as_view(),name='login'),
    path('auth/logout',LogoutView.as_view(),name='logout'),
    path('activate/<uidb64>/<token>',ActivateAccountView.as_view(),name='activate'),
]
