from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path('register/<str:user_type>', views.register_user, name='register-user'),
]
