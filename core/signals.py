from datetime import timedelta
from django.db.models.signals import post_save
from django.dispatch import receiver

from core.utils import generate_random_id
from .models import (
    DigitizationCertificate,
    DigitizationRequest,
    Payment,
    DigitizationPayment,
    Transaction,
)


@receiver(post_save, sender=DigitizationPayment)
def post_digitization_payment(sender, instance, created, **kwargs):
    if created:
        Transaction.objects.create(
            related_id=created.id,
            reference_code=created.payment_reference,
            amount=created.amount,
            status=created.status,
            payment_gateway=created.payment_gateway,
            transaction_type="digitization",
            currency=created.currency,
            user=created.user,
            transaction_title="Digitization request"
            f"payment for {created.user.email}",
        )


@receiver(post_save, sender=Payment)
def post_application_payment(sender, instance, created, **kwargs):
    if created:
        Transaction.objects.create(
            related_id=created.id,
            reference_code=created.payment_reference,
            amount=created.amount,
            status=created.status,
            payment_gateway=created.payment_gateway,
            transaction_type="application",
            currency=created.currency,
            user=created.user,
            transaction_title=f"Certificate application "
            f"payment for {created.user.email}",
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
