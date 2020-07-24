from django.urls import path
from django.conf.urls import url
from account import views

urlpatterns = [
    path('', views.signup, name='signup'),
    path('userlist/',views.UserListView.as_view(),name='home'),
    path('login/',views.login_view,name='login'),
    path('profile/<int:pk>/',views.UserDetailView.as_view(),name='profile'),
    url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',views.activate, name='activate'),
]