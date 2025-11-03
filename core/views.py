from django.shortcuts import render
from django.http import JsonResponse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from django.core.validators import validate_email
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.contrib.auth.password_validation import validate_password, ValidationError as PasswordValidationError
from django.contrib.auth import password_validation, authenticate, login, logout
from .models import Role
from .utils import generate_username, create_audit_log, validate_nin_number
from .serializers import UserRegistrationSerializer, UserLoginSerializer, UserLogoutSerializer
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework.permissions import IsAuthenticated

User = get_user_model()
def index(request):
    return JsonResponse({"message": "Welcome to the Core App!"})


@api_view(['POST'])
def register_user(request, user_type):
    """
    Registers a new user based on the provided user type.
    Args:
        request (Request): The HTTP request object containing user data.
        user_type (str): The type of user to be registered.
    Returns:
        Response: A Response object containing a success message and HTTP status code 201 if the user is successfully created.
                A Response object containing an error message and HTTP status code 400 if there are validation errors or if the user already exists.
    Raises:
        ValidationError: If the provided email address is invalid.
        ObjectDoesNotExist: If there is an error checking for existing users in the database.
    """

    if request.method == "POST":
        valid_account_types = ['applicant', 'super-admin']

        if user_type is None:
            return Response({'error': 'Account type is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        if user_type not in valid_account_types:
            return Response({'error': 'Invalid account type', 'options': [acc for acc in valid_account_types]}, 
                             status=status.HTTP_400_BAD_REQUEST)

        user_serializer = UserRegistrationSerializer(data=request.data)
        if not user_serializer.is_valid():
            return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = user_serializer.validated_data

        email = data['email']
        password = data['password']
        phone_number = data['phone_number']
        nin = data.get('nin', None)

        if user_type != 'super-admin' and not nin:
            return Response({'error': 'NIN is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_email(email)
        except ValidationError:
            return Response({'error': 'Invalid email address'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            password_validation.validate_password(password)
        except ValidationError as e:
            return Response({'error': e.messages}, status=status.HTTP_400_BAD_REQUEST)
        
         # Try cath any existing user email address.
        try:
            existing_user = User.objects.filter(email=email).exists()
            if existing_user:
                return Response({'message': 'email already exist'}, status=status.HTTP_400_BAD_REQUEST)
        except ObjectDoesNotExist:
            pass

        # Try cath any existing user phone number.
        try:
            existing_user = User.objects.filter(phone_number=phone_number).exists()
            if existing_user:
                return Response({'message': 'phone number already exist'}, status=status.HTTP_400_BAD_REQUEST)
        except ObjectDoesNotExist:
            pass

        # Try cath any existing user NIN number.
        try:
            existing_user = User.objects.filter(nin=nin).exists()
            if existing_user:
                return Response({'message': 'NIN already exist'}, status=status.HTTP_400_BAD_REQUEST)
        except ObjectDoesNotExist:
            pass

        if not validate_nin_number(nin):
            return Response({'error': 'Invalid NIN number, must be a valid 11 digit'}, 
                            status=status.HTTP_400_BAD_REQUEST)
        
        user = User.objects.create_user(
            username=generate_username(),
            nin = data.get('nin', None),
            email=data['email'],
            phone_number=data['phone_number'],
            password=data['password'],
        )

        if user_type == 'super-admin':
            role, _ = Role.objects.get_or_create(name='super-admin')
            user.role = role
        
        if user_type == 'applicant':
            role, _ = Role.objects.get_or_create(name='applicant')
            user.role = role

        user.save()
        create_audit_log(
            user=user,
            action_type='create',
            table_name='User',
            record_id=user.id,
            description=f'New {user_type} account created with email {user.email}',
            request=request
        )

        
        return Response({'message': f"{user.role.name} account created successfully!", 
                          'data': [
                                {   'user_id': user.id,
                                    'email': user.email, 
                                    'role': user.role.name,
                                    'phone_number': user.phone_number,
                                }
                          ]},status=status.HTTP_201_CREATED)
    


@api_view(['POST'])
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
            return Response(login_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = login_serializer.validated_data

        email = data['email']
        password = data['password']

        try:
            user = User.objects.get(email=email)
        except ObjectDoesNotExist:
            return Response({'error': 'Invalid email or password'}, status=status.HTTP_404_NOT_FOUND)
        
        user = authenticate(request, email=email, password=password)

        print(f"this is the user value after authenticate method: {user}")

        if user is not None:
            refresh = RefreshToken.for_user(user)
            login(request, user)
            create_audit_log(
                user=user,
                action_type='login',
                table_name='User',
                record_id=user.id,
                description=f'User {user.email} logged in',
                request=request
            )
            return Response({'message': 'Login successful', 'user_id': user.id,
                             'role': user.role.name,
                             'refresh-token': str(refresh),
                             'access-token': str(refresh.access_token)}, 
                        status=status.HTTP_200_OK)
        
        return Response({'error': 'Invalid email or password'}, status=status.HTTP_400_BAD_REQUEST)



@api_view(['POST'])
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
            return Response(logout_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        data = logout_serializer.validated_data
        try:
            access_token = data['access_token']
            token = AccessToken(access_token)
            user_id = token['user_id']
            user = User.objects.get(id=user_id)
            
            # Blacklist the refresh token
            refresh_token = data.get('refresh_token')
            if refresh_token:
                refresh = RefreshToken(refresh_token)
                refresh.blacklist()
            
            # Log out the user
            logout(request)
            create_audit_log(
                user=user,
                action_type='logout',
                table_name='User',
                record_id=user.id,
                description=f'User {user.email} logged out',
                request=request
            )
            return Response({'message': 'Logout successful'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        