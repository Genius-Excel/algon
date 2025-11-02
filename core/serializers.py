from rest_framework import serializers


class UserRegistrationSerializer(serializers.Serializer):
    nin = serializers.CharField(required=False)
    email = serializers.EmailField()
    phone_number = serializers.CharField(max_length=100)
    password = serializers.CharField(max_length=100)