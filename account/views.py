from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect, HttpResponse
from django.contrib.auth.models import User
from django.views.generic import ListView,DetailView
from django.http import HttpResponseRedirect
from django.contrib import messages
from django.contrib.auth import login, authenticate

from .forms import LoginForm,SignUpForm



from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .tokens import account_activation_token
from django.core.mail import EmailMessage


def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()
            current_site = get_current_site(request)
            mail_subject = 'Activate your blog account.'
            message = render_to_string('acc_active_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid':urlsafe_base64_encode(force_bytes(user.pk)),
                'token':account_activation_token.make_token(user),
            })
            to_email = form.cleaned_data.get('email')
            email = EmailMessage(
                        mail_subject, message, to=[to_email]
            )
            email.send()
            messages.success(request,'Please confirm your email address to complete the registration')
            return redirect('/login/')
    else:
        form = SignUpForm()
    return render(request, 'account/signup.html', {'form': form})

def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        messages.success(request,'Thank you for your email confirmation. Now you can login your account.')
        return redirect('/login/')
    else:
        messages.error(request,'Activation link is invalid !')
        return redirect('/login/')


class UserListView(ListView):
    model = User
    template_name = "home.html"

    def get_context_data(self, **kwargs):
        context = super(UserListView, self).get_context_data(**kwargs)
        context['object_list'] = context['object_list'].exclude(username=self.request.user.username)
        return context

    def post(self, request, *args, **kwargs):
        user = request.POST.getlist('user')
        if User.objects.filter(id__in=user):
            username = User.objects.filter(id__in=user)[0].username
            User.objects.filter(id__in=user).delete()
            messages.success(request, 'User {} deleted successfully '.format(username) ,extra_tags='alert')
            return HttpResponseRedirect(self.request.path_info)

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        if User.objects.filter(username=username):
            user = authenticate(username=username, password=password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    return HttpResponseRedirect('/profile/{}'.format(user.id))# Redirect to a success page.
                else:
                    messages.info(request, "Please Activate your account via link sent to your email")
                    return HttpResponseRedirect("/login")
            else:
                messages.error(request, "Wrong Password")
            return HttpResponseRedirect("/login")
        else:
            messages.info(request, "User {} does not exists".format(username) )
            return HttpResponseRedirect("/")
        # return HttpResponseRedirect("/login")
    form=LoginForm()
    return render(request, 'registration/login.html', {'login_form': LoginForm})


class UserDetailView(DetailView):
    model = User
    template_name = "account/profile.html"
