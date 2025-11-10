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
        views.lg_admin_local_government_fee,
        name="local govt application fee",
    ),
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
        views.manage_applications,
        name="My applications",
    ),
    path(
        "admin/dashboard",
        views.lg_admin_dashboard,
        name="local govenment admin dashboard",
    ),
    path(
        "admin/applications",
        views.manage_all_applicants_application,
        name="Manage all applicants applications",
    ),
    path(
        "admin/applications/<str:application_id>",
        views.manage_single_applicants_application,
        name="Manage applicants applications",
    ),
    path(
        "digitization/overview",
        views.lg_digitization_overview,
        name="lg digitization overview",
    ),
]
