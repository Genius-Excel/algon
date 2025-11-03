from django.core.serializers.base import SerializationError
from rest_framework import serializers

from core.models import (
    CertificateApplication,
    LGDynamicField,
    LocalGovernment,
    State,
)


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


class CreateApplicationSerializer(serializers.Serializer):
    """
    Serializer for creating a CertificateApplication.

    This serializer handles both static application fields and dynamic,
    LGA-specific fields required for certificate registration. It validates
    user input and ensures all required fields for a given Local Government (LGA)
    are present before creating a CertificateApplication record.

    Static Fields:
        - full_name (str): Full name of the applicant. Must include first and last name.
        - date_of_birth (date): Applicant's date of birth.
        - phone_number (str): Applicant's phone number. Must match a valid phone pattern.
        - email_address (str): Applicant's email address.
        - state (str): Name of the state. Must exist in the database.
        - lga (str): Name of the local government. Must exist in the database
        under the specified state.
        - village (str): Applicant's village of residence.
        - letter_from_traditional_ruler (str, URL): Optional document URL
        from traditional ruler.

    Dynamic Fields:
        - These are LGA-specific fields defined in LGDynamicField.
        - Validation ensures all required dynamic fields for the applicant's
        LGA are included in the input data.
        - Missing required dynamic fields raise a ValidationError with the
        appropriate message.

    Methods:
        - validate_full_name(value): Ensures full name contains at least first
        and last name.
        - validate_state(value): Confirms state exists in the database.
        - validate_lga(value): Confirms local government exists in the database.
        - validate(attrs): Performs cross-field validation, checks
        required dynamic fields.
        - create(validated_data): Creates a CertificateApplication instance,
          and saves dynamic field responses in ApplicationFieldResponse table.

    Example Usage:
        serializer = CreateApplicationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        application = serializer.save(applicant=request.user)
    """

    full_name = serializers.CharField(max_length=50, required=True)
    date_of_birth = serializers.DateField(required=True)
    phone_number = serializers.RegexField(
        regex=r"^\+?\d{10,15}$",
        error_messages={
            "invalid": "Enter a valid phone number (e.g., +2348012345678)."
        },
        required=True,
    )
    email_address = serializers.EmailField(required=True)
    state = serializers.CharField(required=True)
    lga = serializers.CharField(max_length=50, required=True)
    village = serializers.CharField(max_length=150, required=True)
    letter_from_traditional_ruler = serializers.URLField()

    def validate_lga(self, value):
        """validate that the local government is in the DB"""
        if LocalGovernment.objects.filter(name__iexact=value.strip()).exists():
            return value
        else:
            raise serializers.ValidationError(
                "LocalGovernment matching query does not exist"
            )

    def validate_state(self, value):
        """validate the provided state"""
        if State.objects.filter(name__iexact=value.strip()).exists():
            return value
        else:
            raise serializers.ValidationError(
                "State matching query does not exist"
            )

    def validate_full_name(self, value):
        """validate the full name"""
        full_name_len = value.strip().split(" ")
        if full_name_len < 2:
            raise serializers.ValidationError(
                "Full name must include both first and last names."
            )
        return value

    def validate(self, attrs):
        # validate if the lga requires some fields
        # trad_ruler_letter = attrs.get("letter_from_traditional_ruler")
        local_govt_name = attrs.get("lga")
        state_name = attrs.get("state")
        local_govt = LocalGovernment.objects.filter(
            name=local_govt_name.strip(),
            state__name__iexact=state_name.strip(),
        ).first()
        if not local_govt:
            raise serializers.ValidationError("Local government not found")

        dynamic_fields = LGDynamicField.objects.filter(
            local_government=local_govt, is_required=True
        )

        for field in dynamic_fields:
            if field.field_name not in attrs.get(field.field_name):
                raise serializers.ValidationError(
                    {
                        field.field_name: f"{field.field_label} is "
                        f"required for {local_govt_name}"
                    }
                )

        return attrs

    def create(self, validated_data):
        return CertificateApplication.objects.create(**validated_data)


class LGDynamicFieldSerializer(serializers.ModelSerializer):
    field = ["__all__"]

    class Meta:
        model = LGDynamicField


class AdditionalRequirementSerializer(serializers.Serializer):

    class Meta:
        model = LGDynamicField
