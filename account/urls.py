from django.urls import path
from account import views

urlpatterns = [
    path('', views.signup, name='signup'),
    path('userlist/',views.UserListView.as_view(),name='home'),
    path('login/',views.login_view,name='login'),
    path('profile/<int:pk>/',views.UserDetailView.as_view(),name='profile'),
]