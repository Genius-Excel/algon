from django.db import transaction
from django.conf import settings
from django.db.models import Sum
from django.http import JsonResponse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import (
    api_view,
    permission_classes,
    throttle_classes,
)
from rest_framework.views import PermissionDenied
from celery.result import AsyncResult
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.core.validators import validate_email
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.contrib.auth import (
    password_validation,
    authenticate,
    login,
    logout,
)
from django.utils.timezone import now, timedelta
from core.permissions import (
    CanViewAndApproveRequests,
    IsApplicantUser,
    IsLGAdmin,
)
from core.tasks import cloudinary_upload_task
from .models import (
    AuditLog,
    Certificate,
    CertificateApplication,
    DigitizationPayment,
    DigitizationRequest,
    LGDynamicField,
    LGFee,
    LocalGovernment,
    Payment,
    Role,
)
from .utils import (
    extract_payment_data,
    generate_random_id,
    generate_username,
    create_audit_log,
    get_request_info,
    paystack_url_generate,
    validate_nin_number,
    generate_email_confirmation_token,
    send_email_with_html_template,
)
from .serializers import (
    ApplicationFieldResponseSerializer,
    ApplicationSerializer,
    DigitizationPaymentSerializer,
    DigitizationRequestSerializer,
    DigitizationSerializer,
    LGDynamicFieldSerializer,
    LGFeeSerializer,
    PaymentSerializer,
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserLogoutSerializer,
    ChangePasswordSerializer,
    CreateApplicationSerializer,
)

from .throttles import ResetEmailTwoCallsPerHour
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework.permissions import IsAdminUser, IsAuthenticated


User = get_user_model()


def index(request):
    return JsonResponse({"message": "Welcome to the Core App!"})


@api_view(["POST"])
def register_user(request, user_type):
    """
    Registers a new user based on the provided user type.
    Args:
        request (Request): The HTTP request object containing user data.
        user_type (str): The type of user to be registered.
    Returns:
        Response: A Response object containing a success message and HTTP
                status code 201 if the user is successfully created.
                A Response object containing an error message and HTTP status
                code 400 if there are validation errors or if the user already
                exists.
    Raises:
        ValidationError: If the provided email address is invalid.
        ObjectDoesNotExist: If there is an error checking for
        existing users in the database.
    """

    if request.method == "POST":
        valid_account_types = ["applicant", "super-admin"]

        if user_type is None:
            return Response(
                {"error": "Account type is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if user_type not in valid_account_types:
            return Response(
                {
                    "error": "Invalid account type",
                    "options": [acc for acc in valid_account_types],
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        user_serializer = UserRegistrationSerializer(data=request.data)
        if not user_serializer.is_valid():
            return Response(
                user_serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        data = user_serializer.validated_data

        email = data["email"]
        password = data["password"]
        phone_number = data["phone_number"]
        nin = data.get("nin", None)

        if user_type != "super-admin" and not nin:
            return Response(
                {"error": "NIN is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if user_type != "super-admin":
            if not nin:
                return Response(
                    {"error": "NIN is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not validate_nin_number(nin):
                return Response(
                    {"error": "Invalid NIN number, must be 11 digits"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if User.objects.filter(nin=nin).exists():
                return Response(
                    {"error": "NIN already exists"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        try:
            validate_email(email)
        except ValidationError:
            return Response(
                {"error": "Invalid email address"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            password_validation.validate_password(password)
        except ValidationError as e:
            return Response(
                {"error": e.messages}, status=status.HTTP_400_BAD_REQUEST
            )

        # Try cath any existing user email address.
        try:
            existing_user = User.objects.filter(email=email).exists()
            if existing_user:
                return Response(
                    {"message": "email already exist"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except ObjectDoesNotExist:
            pass

        # Try cath any existing user phone number.
        try:
            existing_user = User.objects.filter(
                phone_number=phone_number
            ).exists()
            if existing_user:
                return Response(
                    {"message": "phone number already exist"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except ObjectDoesNotExist:
            pass

        user = User.objects.create_user(
            username=generate_username(),
            nin=data.get("nin", None),
            email=data["email"],
            phone_number=data["phone_number"],
            password=data["password"],
        )

        if user_type == "super-admin":
            role, _ = Role.objects.get_or_create(name="super-admin")
            user.role = role

        if user_type == "applicant":
            role, _ = Role.objects.get_or_create(name="applicant")
            user.role = role

        user.save()
        create_audit_log(
            user=user,
            action_type="create",
            table_name="User",
            record_id=user.id,
            description=f"New {user_type} account created with email {user.email}",
            request=request,
        )

        return Response(
            {
                "message": f"{user.role.name} account created successfully!",
                "data": [
                    {
                        "user_id": user.id,
                        "email": user.email,
                        "role": user.role.name,
                        "phone_number": user.phone_number,
                    }
                ],
            },
            status=status.HTTP_201_CREATED,
        )


@api_view(["POST"])
def login_user(request):
    """
    Handle user login requests.
    This view function processes POST requests to authenticate a user based on
    their email and password. If the credentials are valid and the user's email
    is verified, it logs the user in and returns a response containing a success
    message, user ID, role, refresh token, and access token. If the credentials
    are invalid or the email is not verified, it returns an appropriate error
    response.
    Args:
        request (HttpRequest): The HTTP request object containing the login data.
    Returns:
        Response: A DRF Response object with the following possible outcomes:
            - 200 OK: If login is successful.
            - 400 Bad Request: If the login data is invalid or email is not verified.
            - 404 Not Found: If the email is not found in the database.
    """

    if request.method == "POST":
        login_serializer = UserLoginSerializer(data=request.data)

        if not login_serializer.is_valid():
            return Response(
                login_serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        data = login_serializer.validated_data

        email = data["email"]
        password = data["password"]

        try:
            user = User.objects.get(email=email)
        except ObjectDoesNotExist:
            return Response(
                {"error": "Invalid email or password"},
                status=status.HTTP_404_NOT_FOUND,
            )

        user = authenticate(request, email=email, password=password)

        print(f"this is the user value after authenticate method: {user}")

        if user is not None:
            refresh = RefreshToken.for_user(user)
            login(request, user)
            create_audit_log(
                user=user,
                action_type="login",
                table_name="User",
                record_id=user.id,
                description=f"User {user.email} logged in",
                request=request,
            )
            return Response(
                {
                    "message": "Login successful",
                    "user_id": user.id,
                    "role": user.role.name,
                    "refresh-token": str(refresh),
                    "access-token": str(refresh.access_token),
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            {"error": "Invalid email or password"},
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_user(request):
    """
    Handle user logout.
    This view handles the logout process for a user. It expects a POST request with
    an access token and optionally a refresh token. The access token is used to
    identify the user, and if a refresh token is provided, it will be blacklisted.
    Args:
        request (HttpRequest): The HTTP request object containing the POST data.
    Returns:
        Response: A Response object with a success message and HTTP 200 status if
                  logout is successful, or an error message and HTTP 400 status if
                  there is an error.
    """

    if request.method == "POST":
        logout_serializer = UserLogoutSerializer(data=request.data)

        if not logout_serializer.is_valid():
            return Response(
                logout_serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

        data = logout_serializer.validated_data
        try:
            access_token = data["access_token"]
            token = AccessToken(access_token)
            user_id = token["user_id"]
            user = User.objects.get(id=user_id)

            # Blacklist the refresh token
            refresh_token = data.get("refresh_token")
            if refresh_token:
                refresh = RefreshToken(refresh_token)
                refresh.blacklist()

            # Log out the user
            logout(request)
            create_audit_log(
                user=user,
                action_type="logout",
                table_name="User",
                record_id=user.id,
                description=f"User {user.email} logged out",
                request=request,
            )
            return Response(
                {"message": "Logout successful"}, status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_400_BAD_REQUEST
            )


@api_view(["POST"])
def reset_password(request):
    """
    Handle password reset requests.
    This view function processes POST requests to reset a user's password.
    It validates the provided passwords, checks if they match, and updates
    the user's password if all validations pass.
    Args:
        request (HttpRequest): The HTTP request object containing the password data.
        token (str): The token used to authenticate the password reset request.
    Returns:
        Response: A DRF Response object with a success or error message and appropriate HTTP status code.
    Possible Responses:
        - 200 OK: Password reset successful.
        - 400 Bad Request: Password fields are required, passwords do not match, or validation errors.
    """

    if request.method == "POST":
        token = request.GET.get("token", None)

        if token is None:
            return Response(
                {"message": "Token is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        password1 = request.data.get("password1", None)
        password2 = request.data.get("password2", None)

        if not password1 or not password2:
            return Response(
                {"message": "Password fields are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if password1 != password2:
            return Response(
                {"message": "Passwords do not match"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # validate password
        try:
            password_validation.validate_password(password1)
        except ValidationError as e:
            return Response(
                {"error": e.messages}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            access_token = AccessToken(token)
            user_id = access_token.payload.get("user_id", None)
            user = get_object_or_404(User, id=user_id)

            user.set_password(password1)
            user.save()
            create_audit_log(
                user=user,
                action_type="update",
                table_name="User",
                record_id=user.id,
                description=f"User {user.email} reset their password",
                request=request,
            )
            return Response(
                {"message": "Password reset successful"},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_400_BAD_REQUEST
            )


@api_view(["POST"])
@throttle_classes([ResetEmailTwoCallsPerHour])
def password_reset_email(request):
    """
    Handles the password reset process.
    This function processes POST requests with an email address and sends a
    password reset link to the user's email address. The link contains a token that is valid for a limited time, after which the user can reset their password. Args:
        request (HttpRequest): The HTTP request object containing the email address.
    Returns:
        Response: A Response object with a success message and HTTP 200 status if
                  the email is successfully sent, or an error message and HTTP 400
                  status if there are validation errors or other issues.
    """
    if request.method == "POST":
        email = request.data.get("email", None)
        if email is None:
            return Response(
                {"error": "Email is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(email=email)
        except ObjectDoesNotExist:
            return Response(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )

        token = generate_email_confirmation_token(user)
        reset_url = (
            f"{settings.FRONTEND_BASE_URL_PASSWORD_RESET}?token={token}"
        )
        # send email to user
        subject = "Password Reset"
        template_file = "templates/core/password-reset.html"
        template_context = {
            "first_name": user.first_name,
            "last_name": user.last_name,
            "reset_url": reset_url,
        }
        sender_name = "ALGON Certificate"
        email_status = send_email_with_html_template(
            template_file, template_context, email, subject, sender_name
        )

        return Response(
            {
                "message": "Password reset email sent",
                "email_status": email_status,
            },
            status=status.HTTP_200_OK,
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def change_password(request):
    """
    Change the password for an authenticated user.
    Args:
        request (HttpRequest): The HTTP request object containing the current
        and new passwords.
    Returns:
        Response: A DRF Response object with a success
        or error message and appropriate HTTP status code.
    """
    if request.method == "POST":
        user_id = request.user.id
        try:
            user = User.objects.get(id=user_id)
        except ObjectDoesNotExist:
            return Response(
                {"message": "No user with such ID"},
                status=status.HTTP_404_NOT_FOUND,
            )

        password_change_serializer = ChangePasswordSerializer(
            data=request.data
        )

        if not password_change_serializer.is_valid():
            return Response(
                password_change_serializer.errors,
                status=status.HTTP_400_BAD_REQUEST,
            )

        data = password_change_serializer.validated_data
        current_password = data.get("current_password")
        new_password = data.get("new_password")
        confirm_new_password = data.get("confirm_password")

        if (
            not current_password
            or not new_password
            or not confirm_new_password
        ):
            return Response(
                {"error": "All password fields are required"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if new_password != confirm_new_password:
            return Response(
                {"error": "New passwords do not match"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not user.check_password(current_password):
            return Response(
                {"error": "Current password is incorrect"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            password_validation.validate_password(new_password, user)
        except ValidationError as e:
            return Response(
                {"error": e.messages}, status=status.HTTP_400_BAD_REQUEST
            )

        user.set_password(new_password)
        user.save()
        create_audit_log(
            user=user,
            action_type="update",
            table_name="User",
            record_id=user.id,
            description=f"User {user.email} changed their password",
            request=request,
        )

        return Response(
            {"message": "Password changed successfully"},
            status=status.HTTP_200_OK,
        )


@api_view(["POST", "PATCH"])
@permission_classes([IsAuthenticated, IsApplicantUser])
def applicant_certificate_application(request):
    """
    Multi-step Certificate Application for applicants.

    POST: Create a new application (step 1 or subsequent steps)
    PATCH: Update existing application for a given step.
    """
    user = request.user

    serializer_class_used = CreateApplicationSerializer

    if CertificateApplication.objects.filter(
        applicant=user, application_status="approved"
    ).exists():
        return Response(
            {"error": "Approved application already exists"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    serializer = serializer_class_used(
        data=request.data, context={"request": request}
    )
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    instance = serializer.save(applicant=user)

    # Handle file uploads asynchronously via Celery
    uploaded_file = request.FILES.get("nin_slip")
    profile_photo = request.FILES.get("profile_photo")

    if uploaded_file:
        cloudinary_upload_task.delay(
            uploaded_file.read(),
            "nin_slip",
            str(instance.id),
            "CertificateApplication",
        )
    if profile_photo:
        cloudinary_upload_task.delay(
            profile_photo.read(),
            "profile_photo",
            str(instance.id),
            "CertificateApplication",
        )

    # Extra LG-specific fields
    extra_fields = LGDynamicField.objects.filter(
        local_government=instance.local_government
    )

    create_audit_log(
        user=user,
        action_type="create",
        table_name="CertificateApplication",
        description=f"Certificate application step {step_number or 1} initiated by {user.email}",
    )

    return Response(
        {
            "data": serializer.data,
            "extra_fields": [
                {
                    "field_label": f.field_label,
                    "field_name": f.field_name,
                    "field_type": f.field_type,
                    "is_required": f.is_required,
                    "field_id": str(f.id),
                }
                for f in extra_fields
            ],
            "application_id": str(instance.id),
        },
        status=status.HTTP_201_CREATED,
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated, IsApplicantUser])
def certificate_application_second_step(request, application_id):
    """
        Handle the second step of the certificate application process.
        This view processes POST requests to handle the second step of a certificate application.
        It validates the provided data and updates the corresponding CertificateApplication instance.
    Args:
        request (HttpRequest): The HTTP request object containing the application data.
        application_id (str): The ID of the CertificateApplication instance to be updated.
    Returns:
        Response: A DRF Response object with a success or error message and appropriate HTTP status code.
    """

    if not application_id:
        return Response(
            {"error": "application_id is required"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    user = request.user

    try:
        application_instance = CertificateApplication.objects.get(
            id=application_id, applicant=user
        )
        residential_address = request.data.get("residential_address", None)
        landmark = request.data.get("landmark", None)
        application_instance.residential_address = residential_address
        application_instance.landmark = landmark
        application_instance.save()
    except CertificateApplication.DoesNotExist:
        return Response(
            {"error": "Application not found"},
            status=status.HTTP_404_NOT_FOUND,
        )
    extra_fields = request.data.get("extra_fields", {})
    # application_field = LGDynamicField.objects.filter(
    #     local_government=instance.local_government,
    # )
    for field_data in extra_fields:
        field_id = field_data.get("field_id", None)
        lg_field = LGDynamicField.objects.filter(id=field_id).first()
        if not lg_field:
            continue
        field_data["field"] = lg_field.id
        field_data["application"] = application_instance.id

        serializer = ApplicationFieldResponseSerializer(
            data=field_data,
        )
        response_instance = serializer.validated_data.get("id")
        if not serializer.is_valid():
            return Response(
                serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )
        # get the field_type
        field_type = getattr(lg_field, "field_type", None)
        if field_type == "file":
            uploaded_file = request.FILES.get(lg_field.field_label)
            if uploaded_file:
                cloudinary_upload_task.delay(
                    file_bytes=uploaded_file.read(),
                    file_type="field_value",
                    application_id=str(response_instance),
                    model="ApplicationFieldResponse",
                )
            else:
                continue
        serializer.save()

        create_audit_log(
            user=user,
            action_type="update",
            table_name="CertificateApplication",
            description=f"Certificate application updated by {user.email}",
        )
        # get the amount charged for the application by the local government
        local_government_fee = LGFee.objects.filter(
            local_government=application_instance.local_government
        ).first()

        serialized_fee = LGFeeSerializer(local_government_fee)
        return Response(
            {"data": serializer.data, "fee": serialized_fee},
            status=status.HTTP_200_OK,
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated, IsApplicantUser])
def verify_certificate(request):
    """
    Verify the status of a certificate

    Args:
        request (Request): The HTTP request object containing user data.

    Returns:
        Response: A Response object containing a success message and HTTP
    """

    cert_id = request.data.get("cert_id", None)
    user = request.user
    if not cert_id:
        return Response(
            {"error": "Ceritificate ID not provided"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    certificate = get_object_or_404(Certificate, id=cert_id)
    create_audit_log(
        user=user,
        action_type="view",
        table_name="Certificate",
        description=(
            f"{user.email} verified certificate {certificate.certificate_number}"
            if certificate
            else f"{user.email} attempted to verify certificate {cert_id}"
        ),
    )
    return Response(
        {
            "status": certificate.application.application_status,
            "certificate_number": certificate.certificate_number,
            "cerfiticate_type": certificate.certificate_type,
            "expiry_date": certificate.expiry_date,
            "verification_code": certificate.verification_code,
        }
    )


@api_view(["GET"])
@permission_classes([IsAuthenticated, IsApplicantUser])
def applicant_local_government_fee(request):
    """
    Applicants can view the fee for a specific Local Government.
    """
    lga_name = request.query_params.get("lga")
    lg_id = request.query_params.get("local_government_id")

    if not lga_name and not lg_id:
        return Response(
            {"error": "Must provide 'lga' or 'local_government_id'"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if lg_id:
        lg = LocalGovernment.objects.filter(id=lg_id).first()
    else:
        lg = LocalGovernment.objects.filter(
            name__iexact=lga_name.strip()
        ).first()

    if not lg:
        return Response({"error": "Local Government not found"}, status=404)

    fee = LGFee.objects.filter(local_government=lg).first()
    if not fee:
        return Response(
            {"error": "Fee not set for this Local Government"}, status=404
        )

    serializer = LGFeeSerializer(fee)
    AuditLog.objects.create(
        table_name="LGFee",
        user=request.user,
        action_type="view",
        description=(
            f"{request.user.email} viewed fee for {lg.name} "
            f"({fee.application_fee} {fee.currency})"
        ),
    )
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(["GET", "POST", "PUT"])
@permission_classes([IsAuthenticated, IsLGAdmin])
def lg_admin_local_government_fee(request, pk):
    """
    Local Government Admins can manage fees for their Local Government.
    Args:
        request (Request): The HTTP request object containing user data.
    Returns:
        Response: A Response object containing a success message and HTTP
        status code 200 for GET and PUT requests, and 201 for POST requests.

    """
    if request.method == "GET":
        lg_id = request.query_params.get("govt_id")
        fees = LGFee.objects.all()
        if lg_id:
            fees = fees.filter(local_government_id=lg_id)

        serializer = LGFeeSerializer(fees, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    elif request.method == "POST":
        serializer = LGFeeSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == "PUT":
        if not pk:
            return Response(
                {"error": "LOcal government ID is required for update"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        lg = get_object_or_404(LocalGovernment, id=pk)
        fee_obj = LGFee.objects.filter(local_government=lg).first()
        if not fee_obj:
            return Response({"error": "Fee object not found"}, status=404)
        serializer = LGFeeSerializer(fee_obj, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([IsAuthenticated, IsApplicantUser])
def certificate_digitization(request):
    user = request.user
    # confirm if the user does not have an existing digitization request
    if DigitizationRequest.objects.filter(
        applicant=user, verification_status="approved"
    ).exists():
        return Response(
            {"error": "User already has an approved digitization request"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if CertificateApplication.objects.filter(
        applicant=user, application_status="approved"
    ).exists():
        return Response(
            {"error": "Approved application already exists"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    serializer = DigitizationRequestSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    serializer.save(applicant=user)
    create_audit_log(
        user=user, action_type="create", table_name="DigitizationRequest"
    )
    return Response({"data": serializer.data}, status=status.HTTP_201_CREATED)


@api_view(["POST"])
@permission_classes([IsAuthenticated, IsApplicantUser])
def initiate_payment(request):
    """
    Initiate a payment for different types of services in the system.

    This endpoint supports payments for:
        - Certificate Applications
        - Digitization Requests

    The frontend must provide the following in the request body:
        - payment_type (str): Type of payment
        ("application", "digitization", etc.)
        - model_id (str, UUID): ID of the target object for the payment
        - amount (decimal): Amount to be paid
        - currency (str, optional): Currency code, defaults to "NGN"
        - payment_gateway (str, optional): Payment
        gateway to use, defaults to "paystack"

    Args:
        request (Request): The HTTP request object containing
        user data and payment info.

    Returns:
        Response:
            201 Created - Payment successfully initiated
                {
                    "message": "Application payment initiated",
                    "payment_id": "<UUID of Payment record>",
                    "transaction_id": "<UUID of Transaction record>"
                }
            400 Bad Request - Missing or invalid fields
                {
                    "error": "<error message>"
                }
            404 Not Found - Target object does not exist
                {
                    "detail": "Not found."
                }

    Notes:
        - Creates a Payment record for the specified type.
        - Creates a generic Transaction record for audit/logging purposes.
        - Extendable to support additional payment types with minimal changes.
    """
    user = request.user
    data = request.data
    application_id = data.get("application_id")
    payment_type = data.get("payment_type")
    amount = data.get("amount", None)

    model_object = None

    if not payment_type or not amount or not application_id:
        return Response(
            {"error": "payment_type, application id and amount are required"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if payment_type.lower() == "application":
        model_object = get_object_or_404(
            CertificateApplication, id=application_id
        )
        if model_object.applicant != user:
            return Response(
                {"error": "Payment must be initiated by the applicant"},
                status=status.HTTP_403_FORBIDDEN,
            )
        # create the transaction entry

    elif payment_type.lower() == "digitization":
        model_object = get_object_or_404(
            DigitizationRequest, id=application_id
        )
        if model_object.applicant != user:
            return Response(
                {"error": "Payment must be initiated by the applicant"},
                status=status.HTTP_403_FORBIDDEN,
            )
    else:
        return Response(
            {
                "error": "Unsupported payment type - must be 'application' or 'digitization'"
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    with transaction.atomic():
        reference = generate_random_id(
            prefix="TRX", use_separator=True, separator="-"
        )
        new_request = request.data.copy()
        new_request.update({"payment_reference": reference})

        new_request.update({"user": user.id})
        new_request.update({"application": model_object.id})
        new_request.update({"email": user.email})

        if payment_type.lower() == "digitization":
            digitization_request = DigitizationRequest.objects.filter(
                id=application_id
            ).first()
            if digitization_request:
                serializer = DigitizationPaymentSerializer(data=new_request)
                serializer.is_valid(raise_exception=True)
                create_audit_log(
                    user=user,
                    action_type="create",
                    table_name="DigitizationPayment",
                    description="Payment initiated by user for digitizing certificate",
                    request=request,
                )
                payment_data = extract_payment_data(serializer.data)
                paystack_response = paystack_url_generate(**payment_data)
                serializer.save()
                if paystack_response.status_code == 200:
                    response = paystack_response.json()
                    return Response(response, status=status.HTTP_200_OK)
                else:
                    response = paystack_response.json()
                    return Response(
                        response, status=status.HTTP_400_BAD_REQUEST
                    )

        elif payment_type.lower().strip() == "application":
            serializer = PaymentSerializer(data=new_request)
            serializer.is_valid(raise_exception=True)
            create_audit_log(
                user=user,
                action_type="create",
                table_name="Payment",
                description="Payment initiated by user for digitizing certificate",
                request=request,
            )
            serializer.save()
            payment_data = extract_payment_data(serializer.data)
            paystack_response = paystack_url_generate(
                **payment_data, email=user.email
            )
            if paystack_response.status_code == 200:
                response = paystack_response.json()
                return Response(response, status=status.HTTP_200_OK)
            else:
                response = paystack_response.json()
                return Response(response, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([IsAuthenticated, IsLGAdmin])
def create_dynamic_response_field(request):

    user = request.user

    local_government = request.data.get("local_government", None)
    if not local_government:
        return Response({"error": "Local government not provided"}, status=400)

    lg = user.admin_permissions.filter(
        local_government=local_government
    ).first()
    if not lg:
        return Response(
            {"error": "You are not assigned to the provided local government"},
            status=400,
        )
    self_check = IsLGAdmin()
    can_create = self_check.has_object_permission(request, None, lg)
    if not can_create:
        return Response(
            {
                "error": "You are not permitted to create additional fields for this local government"
            },
            status=403,
        )

    serializer = LGDynamicFieldSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    serializer.save(created_by=user)

    return Response(serializer.data, status=200)


@api_view(["GET"])
@permission_classes([IsAuthenticated, IsApplicantUser])
def manage_applications(request):
    user = request.user
    application_type = request.query_params.get(
        "application_type", "certificate"
    )  # default to certificate if none
    allowd_params = ["certificate", "digitization"]

    if application_type not in allowd_params:
        return Response(
            {
                "error": "Invalid application type. Must be 'certificate' or 'digitization'."
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
    serializer = None
    if application_type == "certificate":
        certificates = CertificateApplication.objects.filter(applicant=user)
        serializer = ApplicationSerializer(certificates, many=True)
    elif application_type == "digitization":
        digitization_requests = DigitizationRequest.objects.filter(
            applicant=user
        )
        serializer = DigitizationSerializer(digitization_requests, many=True)
    create_audit_log(
        table_name="CertificateApplication",
        user=user,
        action_type="view",
        description=f"{user.email} viewed their certificate applications",
        request=request,
    )

    return Response(serializer.data, status=200)


@api_view(["GET"])
@permission_classes([IsAuthenticated, IsLGAdmin])
def manage_all_applicants_application(request):
    """
    Retrieve all Application instances (certificate or digitization) for LG admins.

    Query Params:
        - application_type: "certificate" | "digitization" (defaults to "certificate")

    Responses:
        200 OK: Returns the serialized data list.
        400 Bad Request: Invalid application_type.
        403 Forbidden: If user lacks permission.
    """
    user = request.user
    application_type = request.query_params.get(
        "application_type", "certificate"
    ).lower()
    allowed_params = {"certificate", "digitization"}

    if application_type not in allowed_params:
        return Response(
            {
                "error": "Invalid application type. Must be 'certificate' or 'digitization'."
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    admin_lgs = user.admin_permissions.values_list(
        "local_government", flat=True
    )

    app_models = {
        "certificate": (CertificateApplication, ApplicationSerializer),
        "digitization": (DigitizationRequest, DigitizationSerializer),
    }

    model, serializer_class = app_models[application_type]
    queryset = model.objects.filter(local_government__in=admin_lgs)
    serializer = serializer_class(queryset, many=True)

    create_audit_log(
        description=f"{user.email} viewed all {application_type} applications",
        table_name=model.__name__,
        action_type="view",
        user=user,
        request=request,
    )

    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(["GET", "PATCH"])
@permission_classes([IsAuthenticated, CanViewAndApproveRequests])
def manage_single_applicants_application(request, application_id):
    """
    Retrieve or update a CertificateApplication instance for LG admins and super admins.

    GET:
        - Returns certificate details if the requesting user has access.
        - Logs all access attempts in AuditLog.
    PATCH:
        - Allows LG admins and super admins to approve or reject a certificate.
        - Checks that the certificate belongs to the admin's assigned local government.
        - Only users with the `can_approve` permission can perform this action.

    Path Parameters:
        - pk: UUID of the CertificateApplication to retrieve or update.
    Responses:
        200 OK: Successful retrieval or update.
        403 Forbidden: User lacks permissions.
        404 Not Found: Certificate or permissions not found.
        405 Method Not Allowed: Any other HTTP method.
    """
    allowed_application_types = ["certificate", "digitization"]
    user = request.user
    info = get_request_info(request)

    if request.method == "GET":
        action_type = "view"
        if not application_id:
            return Response(
                {"error": "Application ID is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        application_type = request.query_params.get("application_type", None)
        if not application_type:
            return Response(
                {"error": "Application type query param is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # filter the applications based on type i.e certificate or digitization
        if application_type not in allowed_application_types:
            return Response(
                {"error": "Invalid application type"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if application_type == "certificate":
            application = get_object_or_404(
                CertificateApplication, id=application_id
            )

            view_check = CanViewAndApproveRequests()
            if not view_check.has_object_permission(
                request, None, application
            ):
                return Response(
                    {
                        "error": "User permitted to view application of other local governments"
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )
            serializer = ApplicationSerializer(application)
            AuditLog.objects.create(
                description=f"{user.email} viewed {application_type} {application.id}",
                table_name="CertificateApplication",
                action_type=action_type,
                ip_address=info.get("ip"),
                user_agent=info.get("user_agent"),
                user=user,
            )
            return Response(serializer.data, status=200)

        elif application_type == "digitization":
            application = get_object_or_404(
                DigitizationRequest, id=application_id
            )
            view_check = CanViewAndApproveRequests()
            if not view_check.has_object_permission(
                request, None, application
            ):
                return Response(
                    {
                        "error": "User not to view application of other local governments"
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )
            serializer = DigitizationSerializer(application)
            AuditLog.objects.create(
                description=f"{user.email} viewed {application_type} {application.id}",
                table_name="CertificateApplication",
                action_type=action_type,
                ip_address=info.get("ip"),
                user_agent=info.get("user_agent"),
                user=user,
            )
            return Response(serializer.data, status=200)

    if request.method == "PATCH":
        action_type = "update"
        if not application_id:
            return Response(
                {"error": "Application ID is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        application_type = request.data.get("application_type", None)
        action = request.data.get("action", None)
        if not action:
            return Response(
                {"error": "Action field is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not application_type:
            return Response(
                {"error": "Application type is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # filter the applications based on type i.e certificate or digitization
        if application_type not in allowed_application_types:
            return Response(
                {
                    "error": "Invalid application type - must be certificate or digitization"
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        if application_type == "certificate":
            application = get_object_or_404(
                CertificateApplication, id=application_id
            )
            approve_check = CanViewAndApproveRequests()
            if not approve_check.has_object_permission(
                request, None, application
            ):
                return Response(
                    {
                        "error": "User not permitted to approve/reject applications of other local governments"
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )
            serializer = ApplicationSerializer(
                application,
                data=request.data,
                partial=True,
                context={"request": request},
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()
            AuditLog.objects.create(
                description=f"{user.email} {action} {application_type} with {application.id}",
                table_name="CertificateApplication",
                action_type=action_type,
                ip_address=info.get("ip"),
                user_agent=info.get("user_agent"),
                user=user,
            )
            return Response(serializer.data, status=200)

        elif application_type == "digitization":
            application = get_object_or_404(
                DigitizationRequest, id=application_id
            )
            approve_check = CanViewAndApproveRequests()
            if not approve_check.has_object_permission(
                request, None, application
            ):
                return Response(
                    {
                        "error": "User not permitted to approve/reject applications of other local governments"
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )
            serializer = DigitizationSerializer(
                application,
                data=request.data,
                partial=True,
                context={"request": request},
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=200)


@api_view(["GET"])
@permission_classes([IsAuthenticated, IsLGAdmin])
def lg_digitization_overview(request):
    """
    Provide an overview of digitization requests for the authenticated LG admin.
    Args:
        request (Request): The HTTP request object containing user data.
    Returns:
        Response: A Response object containing counts of digitization requests
        by status and overall total.

    """

    user = request.user
    current_month = now().month
    current_year = now().year
    info = get_request_info(request)

    digitizations = DigitizationRequest.objects.filter(
        local_government__in=user.admin_permissions.all().values_list(
            "local_government", flat=True
        )
    ).prefetch_related("payments")

    approved_monthly_counts = digitizations.filter(
        created_at__year=current_year,
        created_at__month=current_month,
        verification_status="approved",
    ).count()

    pending_requests = digitizations.filter(
        verification_status="pending"
    ).count()

    revenue_generated = (
        digitizations.filter(payments__payment_status="successful")
        .aggregate(total_revenue=Sum("payments__amount"))
        .get("total_revenue")
        or 0
    )

    data = {
        "approved_requests_this_month": approved_monthly_counts,
        "pending_requests": pending_requests,
        "revenue_generated": revenue_generated,
    }
    AuditLog.objects.create(
        description=f"{user.email} viewed digitization overview",
        table_name="DigitizationRequest",
        action_type="view",
        ip_address=info.get("ip"),
        user_agent=info.get("user_agent"),
        user=user,
    )

    return Response(data, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([IsAuthenticated, IsLGAdmin])
def lg_admin_dashboard(request):
    """
    Provide an overview of certificate applications and revenue
    for the authenticated LG admin.
    """
    user = request.user
    current_week = now() - timedelta(days=7)
    previous_week = current_week - timedelta(days=7)
    info = get_request_info(request)

    applications = CertificateApplication.objects.filter(
        local_government__in=user.admin_permissions.values_list(
            "local_government", flat=True
        )
    ).prefetch_related("payments")

    approved_qs = applications.filter(application_status="approved")
    pending_qs = applications.filter(application_status="pending")

    total_applications = applications.count()
    approved_count = approved_qs.count()
    pending_count = pending_qs.count()

    approved_this_week = approved_qs.filter(
        created_at__gte=current_week
    ).count()
    approved_last_week = approved_qs.filter(
        created_at__lt=current_week,
        created_at__gte=previous_week,
    ).count()

    approval_ratio = (
        (approved_count / total_applications) * 100
        if total_applications > 0
        else 0
    )

    total_revenue = (
        applications.filter(payment_status="paid")
        .aggregate(total=Sum("payments__amount"))
        .get("total")
        or 0
    )

    revenue_this_week = (
        applications.filter(
            payment_status="paid", created_at__gte=current_week
        )
        .aggregate(total=Sum("payments__amount"))
        .get("total")
        or 0
    )

    revenue_last_week = (
        applications.filter(
            payment_status="paid",
            created_at__lt=current_week,
            created_at__gte=previous_week,
        )
        .aggregate(total=Sum("payments__amount"))
        .get("total")
        or 0
    )

    revenue_increase_percentage = (
        ((revenue_this_week - revenue_last_week) / revenue_last_week) * 100
        if revenue_last_week > 0
        else (100 if revenue_this_week > 0 else 0)
    )

    data = {
        "approved_applications": approved_count,
        "approved_this_week": approved_this_week,
        "approved_last_week": approved_last_week,
        "pending_applications": pending_count,
        "approval_ratio": approval_ratio,
        "revenue_generated": total_revenue,
        "revenue_this_week": revenue_this_week,
        "revenue_last_week": revenue_last_week,
        "revenue_increase_percentage": revenue_increase_percentage,
        "total_applications": total_applications,
    }

    AuditLog.objects.create(
        description=f"{user.email} viewed LG admin dashboard",
        table_name="CertificateApplication",
        action_type="view",
        ip_address=info.get("ip"),
        user_agent=info.get("user_agent"),
        user=user,
    )

    return Response(data, status=status.HTTP_200_OK)


@api_view(["GET"])
def health_check():
    """
        Health check endpoint to verify that the service is running.

    Returns:
            Response: A Response object with a success message and HTTP 200 status.
    """
    return Response(
        {"status": "Service is running"}, status=status.HTTP_200_OK
    )
