from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path('register/<str:user_type>', views.register_user, name='register-user'),
    path('auth/login', views.login_user, name='login-user'),
    path('auth/logout', views.logout_user, name='logout-user'),
]
