import uuid
from django.conf import settings
from django.db import models
from django.utils import timezone

# def upload_to_profile(instance, filename):
#     # e.g. uploads/profile_photos/<user-id>/<YYYY>/<MM>/<filename>
#     return f"uploads/profile_photos/{instance.applicant_id if hasattr(instance, 'applicant_id') else instance.id}/{timezone.now().year}/{timezone.now().month}/{filename}"

# def upload_to_nin_slip(instance, filename):
#     return f"uploads/nin_slips/{instance.applicant_id if hasattr(instance, 'applicant_id') else instance.id}/{timezone.now().year}/{timezone.now().month}/{filename}"

# def upload_to_uploaded_certificate(instance, filename):
#     return f"uploads/old_certificates/{instance.applicant_id if hasattr(instance, 'applicant_id') else instance.id}/{timezone.now().year}/{timezone.now().month}/{filename}"

class Role(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)  # applicant, lg_admin, super_admin, immigration_officer
    description = models.CharField(max_length=250, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class State(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class LocalGovernment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    state = models.ForeignKey(State, related_name="local_governments", on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("name", "state")

    def __str__(self):
        return f"{self.name} ({self.state.name})"

class AdminPermission(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    admin = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="admin_permissions")
    local_government = models.ForeignKey(LocalGovernment, on_delete=models.CASCADE, related_name="admin_permissions")
    can_approve = models.BooleanField(default=True)
    can_export = models.BooleanField(default=True)
    can_manage_settings = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class LGFee(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    local_government = models.OneToOneField(LocalGovernment, on_delete=models.CASCADE, related_name="fees")
    application_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    digitization_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    regeneration_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    currency = models.CharField(max_length=10, default="NGN")
    last_updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

class LGDynamicField(models.Model):
    FIELD_TYPES = (
        ("text", "Text"),
        ("number", "Number"),
        ("date", "Date"),
        ("file", "File"),
        ("select", "Select"),
    )
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    local_government = models.ForeignKey(LocalGovernment, on_delete=models.CASCADE, related_name="dynamic_fields")
    field_label = models.CharField(max_length=150)
    field_name = models.CharField(max_length=150)  # developer-friendly name
    field_type = models.CharField(max_length=50, choices=FIELD_TYPES)
    is_required = models.BooleanField(default=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("local_government", "field_name")

    def __str__(self):
        return f"{self.local_government.name} - {self.field_label}"

class CertificateApplication(models.Model):
    STATUS_CHOICES = (
        ("pending", "Pending"),
        ("under_review", "Under Review"),
        ("approved", "Approved"),
        ("rejected", "Rejected"),
    )
    PAYMENT_STATUS = (
        ("unpaid", "Unpaid"),
        ("paid", "Paid"),
        ("refunded", "Refunded"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    applicant = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="applications")
    nin = models.CharField(max_length=20)
    full_name = models.CharField(max_length=255)
    date_of_birth = models.DateField()
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    state = models.ForeignKey(State, on_delete=models.SET_NULL, null=True)
    local_government = models.ForeignKey(LocalGovernment, on_delete=models.SET_NULL, null=True)
    village = models.CharField(max_length=150, blank=True, null=True)
    residential_address = models.TextField(blank=True, null=True)
    landmark = models.CharField(max_length=255, blank=True, null=True)
    letter_from_traditional_ruler = models.FileField(upload_to="uploads/letters/%Y/%m/%d/", blank=True, null=True)

    profile_photo = models.URLField(max_length=500, blank=True, null=True)
    nin_slip = models.URLField(max_length=500, blank=True, null=True)

    application_status = models.CharField(max_length=50, choices=STATUS_CHOICES, default="pending")
    payment_status = models.CharField(max_length=50, choices=PAYMENT_STATUS, default="unpaid")
    remarks = models.TextField(blank=True, null=True)
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="approved_applications")
    approved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["nin"]),
            models.Index(fields=["local_government"]),
        ]

    def __str__(self):
        return f"{self.full_name} - {self.nin}"

class ApplicationFieldResponse(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    application = models.ForeignKey(CertificateApplication, on_delete=models.CASCADE, related_name="field_responses")
    field = models.ForeignKey(LGDynamicField, on_delete=models.CASCADE)
    field_value = models.TextField(blank=True, null=True)  # store path for files or the text value
    created_at = models.DateTimeField(auto_now_add=True)

class Payment(models.Model):
    STATUS = (
        ("pending", "Pending"),
        ("successful", "Successful"),
        ("failed", "Failed"),
        ("refunded", "Refunded"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    application = models.ForeignKey(CertificateApplication, on_delete=models.CASCADE, related_name="payments")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="payments")
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_reference = models.CharField(max_length=100, unique=True)
    payment_gateway = models.CharField(max_length=50, blank=True, null=True)
    payment_status = models.CharField(max_length=50, choices=STATUS, default="pending")
    payment_date = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)

class Certificate(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    application = models.OneToOneField(CertificateApplication, on_delete=models.CASCADE, related_name="certificate")
    certificate_number = models.CharField(max_length=50, unique=True)
    certificate_type = models.CharField(max_length=50, default="original")  # original, digitized, regenerated
    issue_date = models.DateField(default=timezone.now)
    expiry_date = models.DateField(blank=True, null=True)
    verification_code = models.CharField(max_length=100, unique=True)
    file_path = models.FileField(upload_to="uploads/certificates/%Y/%m/%d/")
    is_revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["verification_code"]),
        ]

class DigitizationRequest(models.Model):
    VERIFICATION_STATUS = (
        ("pending", "Pending"),
        ("under_review", "Under Review"),
        ("approved", "Approved"),
        ("rejected", "Rejected"),
    )
    PAYMENT_STATUS = (
        ("unpaid", "Unpaid"),
        ("paid", "Paid"),
        ("refunded", "Refunded"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    applicant = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="digitization_requests")
    nin = models.CharField(max_length=20)
    full_name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    state = models.ForeignKey(State, on_delete=models.SET_NULL, null=True)
    local_government = models.ForeignKey(LocalGovernment, on_delete=models.SET_NULL, null=True)
    uploaded_certificate = models.URLField(max_length=500, blank=True, null=True)
    certificate_reference_number = models.CharField(max_length=100, blank=True, null=True)

    # NEW FIELDS for digitization requests
    profile_photo = models.URLField(max_length=500, blank=True, null=True)
    nin_slip = models.URLField(max_length=500, blank=True, null=True)

    payment_status = models.CharField(max_length=50, choices=PAYMENT_STATUS, default="unpaid")
    verification_status = models.CharField(max_length=50, choices=VERIFICATION_STATUS, default="pending")
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="digitization_reviewed")
    reviewed_at = models.DateTimeField(null=True, blank=True)
    remarks = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class DigitizationCertificate(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    digitization_request = models.OneToOneField(DigitizationRequest, on_delete=models.CASCADE, related_name="digitized_certificate")
    certificate_number = models.CharField(max_length=50, unique=True)
    verification_code = models.CharField(max_length=100, unique=True)
    issue_date = models.DateField(default=timezone.now)
    expiry_date = models.DateField(blank=True, null=True)
    file_path = models.FileField(upload_to="uploads/digitized_certificates/%Y/%m/%d/")
    certificate_type = models.CharField(max_length=50, default="digitized")
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

class DigitizationPayment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    digitization_request = models.ForeignKey(DigitizationRequest, on_delete=models.CASCADE, related_name="payments")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_reference = models.CharField(max_length=100, unique=True)
    payment_gateway = models.CharField(max_length=50, blank=True, null=True)
    payment_status = models.CharField(max_length=50, default="pending")
    payment_date = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)

class Transaction(models.Model):
    STATUS = (
        ("pending", "Pending"),
        ("successful", "Successful"),
        ("failed", "Failed"),
        ("canceled", "Canceled"),
        ("refunded", "Refunded"),
    )
    TRANSACTION_TYPES = (
        ("application", "Application"),
        ("digitization", "Digitization"),
        ("regeneration", "Regeneration"),
        ("refund", "Refund"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="transactions")
    transaction_title = models.CharField(max_length=150)
    transaction_type = models.CharField(max_length=50, choices=TRANSACTION_TYPES)
    related_id = models.UUIDField(null=True, blank=True)  # store related application or digitization_request uuid
    reference_code = models.CharField(max_length=100, unique=True)
    payment_gateway = models.CharField(max_length=50, blank=True, null=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=10, default="NGN")
    status = models.CharField(max_length=50, choices=STATUS, default="pending")
    response_message = models.TextField(blank=True, null=True)
    initiated_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

class VerificationLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    certificate = models.ForeignKey(Certificate, on_delete=models.CASCADE, null=True, blank=True)
    digitization_certificate = models.ForeignKey(DigitizationCertificate, on_delete=models.CASCADE, null=True, blank=True)
    verifier_role = models.CharField(max_length=50, blank=True, null=True)
    verifier_info = models.CharField(max_length=255, blank=True, null=True)
    verification_status = models.CharField(max_length=50)
    verified_at = models.DateTimeField(default=timezone.now)

class AuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=150)  # e.g. "Approved Certificate", "Updated Fee"
    module = models.CharField(max_length=100, blank=True, null=True)
    target_table = models.CharField(max_length=100, blank=True, null=True)
    target_id = models.UUIDField(null=True, blank=True)
    ip_address = models.CharField(max_length=45, blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["user"]),
            models.Index(fields=["action"]),
        ]
