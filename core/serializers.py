from rest_framework import serializers


class UserRegistrationSerializer(serializers.Serializer):
    nin = serializers.CharField(required=False)
    email = serializers.EmailField(required=True)