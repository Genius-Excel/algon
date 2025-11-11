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
        "certificates/applications/apply",
        views.applicant_certificate_application,
        name="certificate apply",
    ),
    path(
        "certificates/applications/apply/<str:application_id>",
        views.certificate_application_second_step,
        name="certificate apply step two",
    ),
    path(
        "application-fees/local-government",
        views.lg_admin_local_government_fee,
        name="local govt application fee",
    ),
    path(
        "certificate/digitizations/apply",
        views.applicant_digitization_application,
        name="applicant certificate digitization",
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
    path("payment/webhook", views.paystack_webhook, name="payment webhook"),
    path(
        "admin/create-response-field",
        views.create_dynamic_response_field,
        name="Create dynaic response field",
    ),
    path(
        "certificate/initiate-payment",
        views.initiate_payment,
        name="initiate payment",
    ),
]
