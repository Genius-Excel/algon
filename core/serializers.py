from rest_framework import serializers


class UserRegistrationSerializer(serializers.Serializer):
    nin = serializers.CharField(required=False)
    email = serializers.EmailField()
    phone_number = serializers.CharField(max_length=100)
    password = serializers.CharField(max_length=100)


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    nin = serializers.CharField(required=False)
    password = serializers.CharField(max_length=100)


class UserLogoutSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
    refresh_token = serializers.CharField(required=True)


class ChangePasswordSerializer(serializers.Serializer):
    current_password = serializers.CharField(max_length=100)
    new_password = serializers.CharField(max_length=100)
    confirm_password = serializers.CharField(max_length=100)
