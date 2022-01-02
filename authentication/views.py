from django.shortcuts import render,redirect
from django.views.generic import View
from django.contrib import messages
from validate_email import validate_email
from django.contrib.auth.models import User

# email validation
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.utils.encoding import force_bytes,force_str,DjangoUnicodeDecodeError
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from .utils import generate_tokens
from django.core.mail import EmailMessage
from django.conf import settings

# login 
from django.contrib.auth import authenticate,login,logout

import threading

# Create your views here.


class HomeView(View):
    template_name = 'home.html'
    def get(self, request, *args, **kwargs):
        return render(request,self.template_name)


class EmailTreading(threading.Thread):
    def __init__(self, email_message):
        self.email_message = email_message
        threading.Thread.__init__(self)

    def run(self):
        self.email_message.send()

class RegistrationView(View):
    template_name = 'auth/register.html'
    def get(self, request, *args, **kwargs):
        return render(request,self.template_name)

    def post(self, request, *args, **kwargs):
        context = {
            'data' : request.POST,
            'has_error': False,
        }
        email = request.POST.get('email')
        username = request.POST.get('username')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')

        if len(password) < 6:
            messages.add_message(request,messages.ERROR,'Password must be at least 6 characters')
            context['has_error'] = True

        if password2 != password:
            messages.add_message(request,messages.ERROR,"Password don't match")
            context['has_error'] = True

        if not validate_email(email):
            messages.add_message(request,messages.ERROR,'Invalid email.Please enter a valid email')
            context['has_error'] = True

        try:
            if User.objects.filter(email=email).exists():
                messages.add_message(request,messages.ERROR,'Email is already taken')
                context['has_error'] = True
        except:
            print("An exception occurred")

        try:
            if User.objects.filter(username=username).exists():
                messages.add_message(request,messages.ERROR,'Username is already taken')
                context['has_error'] = True
        except:
            print("An exception occurred")

        if context['has_error']:
            return render(request,self.template_name,context)

        user = User.objects.create_user(username=username, email=email)
        user.set_password(password)
        user.first_name=first_name
        user.last_name=last_name
        user.is_active=False
        user.save()

# email validation
        current_site = get_current_site(request)
        email_subject = 'Active your Account'
        message = render_to_string('auth/activate.html',{
            'user':user,
            'domain':current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_tokens.make_token(user),
        }
        )
        email_message = EmailMessage(
            email_subject,
            message,
            settings.EMAIL_HOST_USER,
            [email]
        )

        # email_message.send()
        EmailTreading(email_message).start()
        messages.add_message(request,messages.SUCCESS,'Account create successful.Please cheek your mail and active your account')
        return redirect('login')


class LoginView(View):
    template_name = 'auth/login.html'
    context={}
    def get(self, request, *args, **kwargs):
        return render(request,self.template_name,self.context)

    def post(self, request, *args, **kwargs):
        context={
            'data': request.POST,
            'has_error': False
        }
        username = request.POST.get('username')
        password = request.POST.get('password')
        if username =='':
            messages.add_message(request,messages.ERROR,'Username is required')
            context['has_error'] = True
        if password == '':
            messages.add_message(request,messages.ERROR,'Password is required')
            context['has_error'] = True

        user = authenticate(username=username,password=password)
        if not user and not context['has_error']:
            messages.add_message(request,messages.ERROR,'Invalid username or password')
            context['has_error'] = True

        if context['has_error']:
            return render(request,self.template_name,self.context)
        
        login(request,user)
        return redirect('home')


class LogoutView(View):
    def post(self, request, *args, **kwargs):
        logout(request)
        messages.add_message(request,messages.SUCCESS,'Logout successful')
        return redirect('login')


class ActivateAccountView(View):
    template_name = 'auth/activate_failed'
    def get(self, request, uidb64,token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except:
            user = None

        if user is not None and generate_tokens.check_token(user,token):
            user.is_active = True
            user.save()
            messages.add_message(request,messages.INFO,'Account activated successful')
            return redirect('login')
        return render(request,self.template_name,status=401)

    def post(self, request, *args, **kwargs):
        pass

