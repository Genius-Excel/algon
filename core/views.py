from http.client import HTTPResponse
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
from .models import (
    Certificate,
    CertificateApplication,
    LGDynamicField,
    LocalGovernment,
    Role,
)
from .utils import (
    generate_username,
    create_audit_log,
    validate_nin_number,
    generate_email_confirmation_token,
    send_email_with_html_template,
)
from .serializers import (
    LGDynamicFieldSerializer,
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
    if request.method == "POST":
        # confirm if user is an applicant, does not have an
        # existing approved certificate application request
        user = request.user
        if user.role != "applicant":
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

        serializer = CreateApplicationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
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

    certificate = get_object_or_404(Certificate, certificate_id=cert_id)
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
