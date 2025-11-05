from http.client import HTTPResponse
import tempfile
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.db import transaction
from django.http.request import HttpRequest
from django.shortcuts import render
from django.conf import settings
from django.http import JsonResponse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import (
    api_view,
    permission_classes,
    throttle_classes,
)
from celery.result import AsyncResult
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.core.validators import validate_email
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.contrib.auth.password_validation import (
    validate_password,
    ValidationError as PasswordValidationError,
)
from django.contrib.auth import (
    password_validation,
    authenticate,
    login,
    logout,
)

from core.tasks import cloudinary_upload_task
from .models import (
    Certificate,
    CertificateApplication,
    DigitizationPayment,
    DigitizationRequest,
    LGDynamicField,
    LGFee,
    LocalGovernment,
    Role,
    Transaction,
)
from .utils import (
    generate_random_id,
    generate_username,
    create_audit_log,
    upload_file_to_cloudinary,
    validate_nin_number,
    generate_email_confirmation_token,
    send_email_with_html_template,
)
from .serializers import (
    DigitizationRequestSerializer,
    FileUploadSerializer,
    LGDynamicFieldSerializer,
    LGFeeSerializer,
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserLogoutSerializer,
    ChangePasswordSerializer,
    CreateApplicationSerializer,
)

from .throttles import ResetEmailTwoCallsPerHour
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework.permissions import IsAuthenticated

from core import serializers

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
    password reset link to the user's email address. The link contains a token
    that is valid for a limited time, after which the user can reset their password.
    Args:
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


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_certificate_application(request):
    """
    Create the local goverment Certificate for the applicant

    Args: request (HttpRequest): The HTTP request object containing the request body

    Returns: HTTPResponse 201 when application has been created

    """
    # confirm if user is an applicant, does not have an
    # existing approved certificate application request
    user = request.user
    role = getattr(user.role, "name", "")
    if role != "applicant":
        return Response(
            {"error": "User is not an applicant"},
            status=status.HTTP_403_FORBIDDEN,
        )
    if CertificateApplication.objects.filter(
        applicant=user, application_status="approved"
    ).exists():
        return Response(
            {"error": "Approved application already exists"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if DigitizationRequest.objects.filter(
        applicant=user, verification_status="approved"
    ).exists():
        return Response(
            {"error": "User already has an approved digitization request"},
            status=status.HTTP_400_BAD_REQUEST,
        )
    serializer = CreateApplicationSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    else:
        serializer.save(applicant=user)
        create_audit_log(
            user=user,
            action_type="create",
            table_name="CertificateApplication",
            description=f"New certificate application initiated by {user.email}",
        )
        return Response(
            {
                "data": serializer.data,
            },
            status=status.HTTP_201_CREATED,
        )


@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def additional_registration_requirements(request):
    """
    Retrieve additional registration requirements for a given Local Government.

    Example:
        GET /api/requirements?lga=Ikoyi
        POST /api/requirements

    Returns:
        200: List of required fields for that LGA
        400: If LGA not found or missing
    """
    if request.method == "GET":
        lga_param = request.query_params.get("lga", None)
        state_param = request.query_params.get("state", None)
        if not lga_param:
            return Response(
                {"error": "Missing lga query param"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not state_param:
            return Response(
                {"error": "Missing state query param"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        local_goverment = LocalGovernment.objects.filter(
            name__iexact=lga_param, state__name__iexact=state_param.strip()
        ).first()
        if not local_goverment:
            return Response(
                {"error": "Local government under state does not exist"}
            )
        dynamic_fields = LGDynamicField.objects.filter(
            local_government=local_goverment
        )
        data = [
            {
                "field_label": f.field_label,
                "field_name": f.field_name,
                "field_type": f.field_type,
                "is_required": f.is_required,
            }
            for f in dynamic_fields
        ]

        return Response({"data": data}, status=status.HTTP_200_OK)

    if request.method == "POST":
        # confirm that the user is allowed to create extra fields
        # TODO: check the local government the user is assigned to. needed to attach fields to the model
        user = request.user
        if user.role != "lg_admin":
            return Response(
                {
                    "error": "Unable to perform action",
                    status: status.HTTP_403_FORBIDDEN,
                }
            )

        serializer = LGDynamicFieldSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(created_by=user)

        return Response(
            {"data": serializer.data}, status=status.HTTP_201_CREATED
        )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
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


@api_view(["GET", "POST", "PUT"])
@permission_classes([IsAuthenticated])
def local_goverment_fees(request):
    """Retrieve and set the application fee for applying for certification
    Args:
        request: The Request Object

        returns:
            GET - 200 if found or 404 if not found
            POST:
                201 (Created) - Fee found
                403 (Forbidden) - User with lesser privileges attempts to modify data
                400 (BAD Request) - Malformed data sent

            PUT:
                200 (OK) - modified

        Returns:
            Response
    """

    if request.method == "GET":
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
            return Response(
                {"error": "Local Government not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        fee = LGFee.objects.filter(local_government=lg).first()
        if not fee:
            return Response(
                {"error": "Fee not set for this Local Government"},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = LGFeeSerializer(fee)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # TODO: add post requues for lg admin to update the pricing


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def handle_uploads(request):
    """
    Handles file uploads asynchronously via Celery.

    Expects multipart/form-data with:
        - file: the uploaded file
        - file_type: the purpose (e.g., 'nin_slip', 'profile_photo')

    Returns:
        {
            "task_id": "<celery_task_id>"
        }
    """
    serializer = FileUploadSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)

    uploaded_file = serializer.validated_data.get("file")
    file_type = serializer.validated_data.get("file_type")
    if not uploaded_file or not file_type:
        return Response(
            {"error": "File and file_type are required"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        for chunk in uploaded_file.chunks():
            tmp_file.write(chunk)
        tmp_file_path = tmp_file.name
    task = cloudinary_upload_task.delay(tmp_file_path, file_type)
    return Response({"task_id": task.id}, status=status.HTTP_202_ACCEPTED)


@api_view(["GET"])
def upload_status(request, task_id) -> Response:
    """Request status for an asynchronous upload
    Args:
        request: Request
    Returns:
        Response object with the data dict
    """
    result = AsyncResult(task_id)
    data = {"status": result.status}
    if result.ready() and result.successful():
        data["file_url"] = result.result
    return Response(data)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
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
@permission_classes([IsAuthenticated])
def initiate_payment(request):
    """
    Initiate a payment for different types of services in the system.

    This endpoint supports payments for:
        - Certificate Applications
        - Digitization Requests
        - (Extendable to other payment types)

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
    role = getattr(user.role, "name", "")
    if role != "applicant":
        return Response(
            {"error": "User is not an applicant"},
            status=status.HTTP_403_FORBIDDEN,
        )
    payment_type = data.get("payment_type")
    model_id = data.get("related_id")
    payment_gateway = data.get("payment_gateway", "paystack")
    amount = data.get("amount", None)

    model_object = None

    if not payment_type or not model_id or not amount:
        return Response(
            {"error": "payment_type, related_id and amount are required"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if payment_type.lower() == "application":
        model_object = get_object_or_404(CertificateApplication, id=model_id)
        if model_object.application != user:
            return Response(
                {"error": "Payment must be initiated by the applicant"},
                status=status.HTTP_403_FORBIDDEN,
            )
        # create the transaction entry

    elif payment_type.lower() == "digitization":
        model_object = get_object_or_404(DigitizationRequest, id=model_id)
        if model_object.application != user:
            return Response(
                {"error": "Payment must be initiated by the applicant"},
                status=status.HTTP_403_FORBIDDEN,
            )
        reference = generate_random_id(prefix="TRX", use_separator=True)

    else:
        return Response(
            {"error": "Unsupported payment type"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    with transaction.atomic():
        reference = generate_random_id(
            prefix="TRX", use_separator=True, separator="-"
        )

        if payment_type.lower() == "digitization":
            digitization_request = DigitizationRequest.objects.filter(
                id=model_id
            ).first()
            if digitization_request:
                payment_entry = DigitizationPayment.objects.create(
                    amount=amount,
                    payment_reference=reference,
                    payment_gateway=payment_gateway,
                    user=user,
                    digitization_request=digitization_request,
                )
                create_audit_log(
                    user=user,
                    action_type="create",
                    table_name="DigitizationPayment",
                    description="Payment initiated by user for digitizing certificate",
                )
                # send to the relevant payment api
                return Response(
                    {
                        "message": f"{payment_type.capitalize()} payment initiated",
                        "payment_id": str(payment_entry.id),
                    },
                    status=status.HTTP_201_CREATED,
                )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def my_applications(request):

    user = request.user
    user_role = getattr(user.role, "role", "")
    if user_role == "applicant":
        
