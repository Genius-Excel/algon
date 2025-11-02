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
from .utils import generate_username, create_audit_log
from .serializers import UserRegistrationSerializer

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

        user = User.objects.create_user(
            username=generate_username(),
            first_name=data['first_name'],
            last_name=data['last_name'],
            email=data['email'],
            phone_number=data['phone_number'],
            password=data['password'],
        )

        if user_type == 'admin':
            role, _ = Role.objects.get_or_create(name='Admin')
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
                                    'first_name': user.first_name,
                                    'last_name': user.last_name,
                                    'email': user.email, 
                                    'role': user.role.name,
                                    'phone_number': user.phone_number,
                                    'email_verified': user.email_verified

                                }
                          ]},status=status.HTTP_201_CREATED)
    
