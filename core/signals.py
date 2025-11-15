from datetime import timedelta
from django.utils.timezone import now
from dateutil.relativedelta import relativedelta

from django.db.models.signals import post_save
from django.dispatch import receiver

from core.utils import generate_random_id

from .models import (
    AdminPermission,
    Certificate,
    CertificateApplication,
    CustomUser,
    DigitizationCertificate,
    DigitizationRequest,
)


@receiver(post_save, sender=DigitizationRequest)
def issue_digitization_certificate(sender, instance, created, **kwargs):
    if (
        instance.verification_status == "approved"
        and instance.payment_status == "paid"
    ):
        # Logic to issue digitized certificate
        DigitizationCertificate.objects.create(
            digitization_request=instance,
            approved_by=instance.approved_by,
            issue_date=instance.approval_date,
            expiry_date=timedelta(days=7),
            verification_code=generate_random_id(),
        )


@receiver(post_save, sender=CertificateApplication)
def create_certificate(sender, instance, created, **kwargs):
    if (
        instance.application_status == "approved"
        and instance.payment_status == "paid"
    ):
        # create the certificate application
        current_date = now()
        expiry_date = current_date + relativedelta(days=7)
        Certificate.objects.create(
            application=instance,
            expiry_date=expiry_date,
            issue_date=current_date,
        )


@receiver(post_save, sender=CustomUser)
def create_admin_permission_on_acceptance(sender, instance, created, **kwargs):
    if instance:
        user_role = getattr(instance.role, "name", "")
        if user_role != "lg_admin":
            return
        if instance.email_verified:
            # TODO: find the related state and lg
            admin_permission = AdminPermission.objects.create()
            admin_permission.save()
