from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path(
        "register/<str:user_type>", views.register_user, name="register-user"
    ),
    path("auth/login", views.login_user, name="login-user"),
    path("auth/logout", views.logout_user, name="logout-user"),
    path(
        "certificate/verify",
        views.verify_certificate,
        name="verify_certificate",
    ),
    path(
        "certificates/applications",
        views.create_certificate_application,
        name="certificate apply",
    ),
    path(
        "application-fees/local-government",
        views.local_goverment_fees,
        name="local govt application fee",
    ),
    path("uploads", views.handle_uploads, name="handle file uploads"),
    path(
        "upload-status/<str:task_id>",
        views.upload_status,
        name="upload status",
    ),
    path(
        "certificate/digitization",
        views.certificate_digitization,
        name="certificate digitization",
    ),
    path(
        "certificates/my-applications",
        views.my_applications,
        name="My applications",
    ),
    path("digitization", views.my_digitizations, name="my digitizations"),
]
