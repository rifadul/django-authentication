from django.urls import path
from .views import home,RegistrationView,LoginView,ActivateAccountView

urlpatterns = [
    path('',home),
    path('auth/register',RegistrationView.as_view(),name='register'),
    path('auth/login',LoginView.as_view(),name='login'),
    path('activate/<uidb64>/<token>',ActivateAccountView.as_view(),name='activate'),
]
