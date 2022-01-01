from django.shortcuts import render,redirect
from django.views.generic import View
from django.contrib import messages
from validate_email import validate_email
from django.contrib.auth.models import User

# Create your views here.
def home(request):
    template_name = 'home.html'
    return render(request,template_name)
    
class RegistrationView(View):
    template_name = 'auth/register.html'
    def get(self, request, *args, **kwargs):
        print('get request')
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
        

        # if User.objects.get(username=username).exists():
        #     messages.add_message(request,messages.ERROR,'Username is already taken')
        #     context['has_error'] = True

        if context['has_error']:
            return render(request,self.template_name,context)

        user = User.objects.create_user(username=username, email=email)
        user.set_password(password)
        user.first_name=first_name
        user.last_name=last_name
        user.is_active=False
        user.save()

        messages.add_message(request,messages.SUCCESS,'Account create successful')
        return redirect('register')


class LoginView(View):
    template_name = 'auth/login.html'
    context={}
    def get(self, request, *args, **kwargs):
        return render(request,self.template_name,self.context)

    def post(self, request, *args, **kwargs):
        return render(request,self.template_name,self.context)

