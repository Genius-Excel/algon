"""
Models for the Local Government Certificate Issuance Platform.

This module defines all database models for user management, local government
administration, certificate application workflows, digitization requests,
transactions, auditing, and verification processes.
"""

import uuid
from django.conf import settings
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser


class Role(models.Model):
    """
    Represents the role assigned to users within the system.

    Roles define the level of access and permissions available to a user,
    such as 'Applicant', 'Local Government Admin', 'Super Admin', or 'Immigration Officer'.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)  # applicant, lg_admin, super_admin, immigration_officer
    description = models.CharField(max_length=250, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name
    

class CustomUser(AbstractUser):
    """
    Custom user model extending Django's AbstractUser.

    Stores authentication details and additional user attributes like email,
    phone numbers, NIN, account status, and assigned role.
    """
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=20, blank=True)
    profile_image = models.URLField(blank=True, null=True)
    alternative_number = models.CharField(max_length=20, blank=True, null=True)
    email_verified = models.BooleanField(default=False)
    nin = models.CharField(max_length=20, blank=True, null=True, unique=True)
    account_status = models.CharField(
        max_length=20,
        choices=[("active", "Active"), ("suspended", "Suspended")],
        default="active",
    )
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, related_name="users")
   
    # class Meta:
    #     ordering = ["-created_at"]

    def __str__(self):
        return self.email

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    
    def has_permission(self, permission_name: str) -> bool:
        """
        Check if the user has a specific permission.
        Args:
            permission_name (str): The permission codename to check.
        Returns:
            bool: True if user has the permission, False otherwise.
        """
        return permission_name in self.get_permissions()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = [ 'username' ]

    def save(self, *args, **kwargs):
        if not self.username:
            self.username = self.generate_unique_username()
        
        super().save(*args, **kwargs)


    def generate_unique_username(self):
        """This method generates a unique username for the user upon trying to
           create an object of the `CustomUser` class.
           It queries the database to check if the username already exist.
           Returns:
               unique_username (str): username generated from provided email address.
        """
        base_username = self.email.split('@')[0]

        unique_username = base_username
        counter = 1

        while CustomUser.objects.filter(username=unique_username).exists():
            unique_username = f"{base_username}{counter}"
            counter += 1

        return unique_username

class State(models.Model):
    """
    Represents a state within country.

    Each state may contain multiple Local Government Areas (LGAs).
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=50, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class LocalGovernment(models.Model):
    """
    Represents a Local Government Area (LGA) within a state.

    Each LGA is associated with one state and can have multiple admins,
    applications, and dynamic requirement fields.
    """

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
    """
    Defines specific permissions granted to a Local Government Admin.

    Permissions determine which actions the admin can perform, such as approving
    applications, managing settings, or exporting data.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    admin = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="admin_permissions")
    local_government = models.ForeignKey(LocalGovernment, on_delete=models.CASCADE, related_name="admin_permissions")
    can_approve = models.BooleanField(default=True)
    can_export = models.BooleanField(default=True)
    can_manage_settings = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class LGFee(models.Model):
    """
    Defines application and service fees for a Local Government Area.

    LG admins can configure the fees for certificate applications,
    digitization, and certificate regeneration.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    local_government = models.OneToOneField(LocalGovernment, on_delete=models.CASCADE, related_name="fees")
    application_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    digitization_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    regeneration_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    currency = models.CharField(max_length=10, default="NGN")
    last_updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

class LGDynamicField(models.Model):
    """
    Represents a dynamic requirement field defined by a Local Government Admin.

    Allows each LGA to define additional application fields dynamically,
    such as 'Proof of Residency' or 'Letter from Community Head'.
    """

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
    """
    Represents a certificate application submitted by an applicant.

    Each application contains applicant data, documents, and associated
    review/approval information.
    """

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
    letter_from_traditional_ruler = models.URLField(blank=True, null=True)

    profile_photo = models.URLField(blank=True, null=True)
    nin_slip = models.URLField(blank=True, null=True)

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
    """
    Stores applicant responses for dynamic fields defined by the Local Government.

    Each record corresponds to one dynamic field response for a specific application.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    application = models.ForeignKey(CertificateApplication, on_delete=models.CASCADE, related_name="field_responses")
    field = models.ForeignKey(LGDynamicField, on_delete=models.CASCADE)
    field_value = models.TextField(blank=True, null=True)  # store path for files or the text value
    created_at = models.DateTimeField(auto_now_add=True)

class Payment(models.Model):
    """
    Records all payment transactions related to certificate applications.

    Each payment entry is linked to an applicant and a specific certificate application.
    It captures transaction details such as amount, payment gateway used,
    transaction status, and timestamps for auditing purposes.
    """
     
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
    """
    Represents an issued certificate for an approved application.

    Each certificate contains a unique verification code that can be validated
    by third parties (e.g., embassies). Certificates may be original, digitized,
    or regenerated and can be revoked by authorized administrators.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    application = models.OneToOneField(CertificateApplication, on_delete=models.CASCADE, related_name="certificate")
    certificate_number = models.CharField(max_length=50, unique=True)
    certificate_type = models.CharField(max_length=50, default="original")  # original, digitized, regenerated
    issue_date = models.DateField(default=timezone.now)
    expiry_date = models.DateField(blank=True, null=True)
    verification_code = models.CharField(max_length=100, unique=True)
    file_path = models.URLField(null=True, blank=True)
    is_revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["verification_code"]),
        ]



class DigitizationRequest(models.Model):
    """
    Represents a request from an applicant to digitize a previously issued hardcopy certificate.

    Applicants upload a scanned version of their existing certificate (and optionally
    a profile photo and NIN slip) to generate a verified digital copy for a reduced fee.
    The request passes through a review process handled by Local Government Admins.
    """

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
    uploaded_certificate = models.URLField(blank=True, null=True)
    certificate_reference_number = models.CharField(max_length=100, blank=True, null=True)

    # NEW FIELDS for digitization requests
    profile_photo = models.URLField(blank=True, null=True)
    nin_slip = models.URLField(blank=True, null=True)

    payment_status = models.CharField(max_length=50, choices=PAYMENT_STATUS, default="unpaid")
    verification_status = models.CharField(max_length=50, choices=VERIFICATION_STATUS, default="pending")
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="digitization_reviewed")
    reviewed_at = models.DateTimeField(null=True, blank=True)
    remarks = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class DigitizationCertificate(models.Model):
    """
    Represents the digital version of a previously hardcopy certificate.

    Created automatically after a digitization request is approved, this model
    stores a new verification code and links to the uploaded digital certificate file.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    digitization_request = models.OneToOneField(DigitizationRequest, on_delete=models.CASCADE, related_name="digitized_certificate")
    certificate_number = models.CharField(max_length=50, unique=True)
    verification_code = models.CharField(max_length=100, unique=True)
    issue_date = models.DateField(default=timezone.now)
    expiry_date = models.DateField(blank=True, null=True)
    file_path = models.URLField(null=True, blank=True)
    certificate_type = models.CharField(max_length=50, default="digitized")
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class DigitizationPayment(models.Model):
    """
    Records payment information for a digitization request.

    Each record tracks the amount, payment reference, gateway used, and current
    payment status associated with a single digitization transaction.
    """

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
    """
    Stores all system-wide financial transactions for traceability and reporting.

    This model provides a unified record of payments related to applications,
    digitization, and other transaction types (e.g., refunds). It is useful for
    analytics, reconciliation, and payment tracking across the entire system.
    """

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
    """
    Tracks all certificate verification attempts.

    Each record logs who performed the verification, their role,
    and whether the verification was successful. It supports both
    original and digitized certificates.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    certificate = models.ForeignKey(Certificate, on_delete=models.CASCADE, null=True, blank=True)
    digitization_certificate = models.ForeignKey(DigitizationCertificate, on_delete=models.CASCADE, null=True, blank=True)
    verifier_role = models.CharField(max_length=50, blank=True, null=True)
    verifier_info = models.CharField(max_length=255, blank=True, null=True)
    verification_status = models.CharField(max_length=50)
    verified_at = models.DateTimeField(default=timezone.now)


class AuditLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, related_name="audit_logs")
    action_type = models.CharField(
        max_length=50,
        choices=[
            ("create", "Create"),
            ("update", "Update"),
            ("delete", "Delete"),
            ("login", "Login"),
            ("logout", "Logout"),
            ("view", "View"),
        ],
    )
    table_name = models.CharField(max_length=150)
    record_id = models.UUIDField(blank=True, null=True)
    changes = models.JSONField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "audit_logs"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user} - {self.action_type} - {self.table_name}"