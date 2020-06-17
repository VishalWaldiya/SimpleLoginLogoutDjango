from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.views.generic import ListView,DetailView
from django.http import HttpResponseRedirect
from django.contrib import messages
from django.contrib.auth import login, authenticate

from .forms import LoginForm,SignUpForm


def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            form.save()
            # username = form.cleaned_data.get('username')
            # raw_password = form.cleaned_data.get('password1')
            # user = authenticate(username=username, password=raw_password)
            # login(request, user)
            return redirect('/login/')
    else:
        form = SignUpForm()
    return render(request, 'account/signup.html', {'form': form})

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
            if user is not None and user.is_active:
                login(request, user)
                return HttpResponseRedirect('/profile/{}'.format(user.id))# Redirect to a success page.
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
