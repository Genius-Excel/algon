from rest_framework import serializers
import datetime

from core.models import (
    AdminPermission,
    CertificateApplication,
    DigitizationRequest,
    LGDynamicField,
    LGFee,
    LocalGovernment,
    State,
)
from core.utils import validate_nin_number


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
        - full_name (str): Full name of the applicant.
            Must include first and last name.
        - date_of_birth (date): Applicant's date of birth.
        - phone_number (str): Applicant's phone number.
            Must match a valid phone pattern.
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
        - validate_lga(value): Confirms local government exists
        in the database.
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
    email = serializers.EmailField(required=True)
    state = serializers.CharField(required=True)
    local_government = serializers.CharField(max_length=50, required=True)
    village = serializers.CharField(max_length=150, required=True)
    letter_from_traditional_ruler = serializers.URLField()
    profile_photo = serializers.URLField()
    nin_slip = serializers.URLField()
    nin = serializers.CharField()
    residential_address = serializers.CharField(max_length=100)
    landmark = serializers.CharField(max_length=50)

    def validate_nin(self, value):
        if not validate_nin_number(value):
            raise serializers.ValidationError("NIN not valid")
        return value

    def validate_local_government(self, value) -> str | None:
        """validate that the local government is in the DB"""
        if LocalGovernment.objects.filter(name__iexact=value.strip()).exists():
            return value
        else:
            raise serializers.ValidationError(
                "LocalGovernment matching query does not exist"
            )

    def validate_state(self, value) -> str | None:
        """validate the provided state"""
        if State.objects.filter(name__iexact=value.strip()).exists():
            return value
        else:
            raise serializers.ValidationError(
                "State matching query does not exist"
            )

    def validate_full_name(self, value) -> str | None:
        """validate the full name"""
        full_name_len = len(value.strip().split(" "))
        if full_name_len < 2:
            raise serializers.ValidationError(
                "Full name must include both first and last names."
            )
        return value

    def validate(self, attrs) -> dict | None:
        # validate if the lga requires some fields
        # trad_ruler_letter = attrs.get("letter_from_traditional_ruler")
        local_govt_name = attrs.get("local_government")
        state_name = attrs.get("state")
        state = State.objects.filter(name__iexact=state_name).first()
        if not state:
            raise serializers.ValidationError("State not found")
        attrs.update({"state": state})
        local_govt = LocalGovernment.objects.filter(
            name=local_govt_name.strip(),
            state=state,
        ).first()
        if not local_govt:
            raise serializers.ValidationError("Local government not found")
        attrs.update({"local_government": local_govt})
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
    class Meta:
        model = LGDynamicField
        fields = "__all__"


class LGFeeSerializer(serializers.ModelSerializer):
    class Meta:
        model = LGFee
        fields = "__all__"

    def to_representation(self, instance) -> dict:
        """
        Customize the serialized output of an LGFee instance.

        This method extends the default serialization behavior provided by
        DRF's `ModelSerializer` to include additional, human-readable fields.

        Specifically:
            - Replaces the `local_government` foreign key with the
              local government's name.
            - Adds the related state's name under the key `"state"`.

        Args:
            instance (LGFee): The LGFee model instance being serialized.

        Returns:
            dict: A dictionary representation of the LGFee object with
                  enriched contextual information suitable for API responses.
        """
        instance_dict = super().to_representation(instance)
        instance_dict["state"] = instance.local_government.state.name
        instance_dict["local_government"] = instance.local_government.name

        return instance_dict


class AdditionalRequirementSerializer(serializers.Serializer):
    class Meta:
        model = LGDynamicField


class DigitizationRequestSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    phone_number = serializers.CharField(max_length=15, required=True)
    nin_slip = serializers.URLField(required=True)
    profile_photo = serializers.URLField(required=True)
    state = serializers.CharField(required=True)
    local_government = serializers.CharField(required=True)
    certificate_reference_number = serializers.CharField(required=True)
    uploaded_certificate = serializers.CharField(required=True)

    def validate_state(self, value):
        """validate the provided state"""
        if State.objects.filter(name__iexact=value.strip()).exists():
            return value
        raise serializers.ValidationError(
            "State matching query does not exist"
        )

    class Meta:
        # fields = "__all__"
        exclude = ("applicant",)
        model = DigitizationRequest


class FileUploadSerializer(serializers.Serializer):
    file = serializers.FileField(required=True)
    file_type = serializers.CharField(max_length=30)


class ApplicationSerializer(serializers.ModelSerializer):
    action = serializers.ChoiceField(
        choices=["approved", "rejected"], write_only=True
    )
    certificate_id = serializers.PrimaryKeyRelatedField(
        write_only=True,
        queryset=CertificateApplication.objects.all(),
    )

    class Meta:
        fields = "__all__"
        model = CertificateApplication

    def validate(self, attrs):
        request_context = self.context.get("request")
        user = request_context.user if request_context else None

        if not user or not user.is_authenticated:
            raise serializers.ValidationError(
                "User not provided or not authenticated"
            )

        permissions = AdminPermission.objects.filter(admin=user).first()
        if not permissions or not permissions.can_approve:
            raise serializers.ValidationError(
                "User not authorized to approve/reject applications"
            )
        certificate = attrs.get("certificate_id")
        if certificate.local_government != permissions.local_government:
            raise serializers.ValidationError(
                "User not authorized to approve/reject applications in this local_government"
            )
        if certificate.payment_status != "paid":
            raise serializers.ValidationError(
                "Application has not been paid for"
            )

        return attrs

    def update(self, instance, validated_data):
        action = validated_data.pop("action", None)
        if action == "approved":
            if instance.application_status == action:
                raise serializers.ValidationError(
                    "Application already approved"
                )
            instance.application_status = action
            instance.approved_at = datetime.datetime.now()
        elif action == "rejected":
            if instance.application_status == action:
                raise serializers.ValidationError(
                    f"Application already {action}"
                )
            instance.application_status = action
        request = self.context.get("request")
        if not request:
            return
        if action == "approved":
            instance.approved_by = request.user
        instance.save()
        return instance

    def to_representation(self, instance):
        representation = super().to_representation(instance)
        if instance.approved_by:
            representation["approved_by"] = {
                "id": instance.approved_by.id,
                "email": instance.approved_by.email,
            }
        return representation


class DigitizationSerializer(serializers.ModelSerializer):
    request_id = serializers.PrimaryKeyRelatedField(
        queryset=DigitizationRequest.objects.all(), write_only=True
    )
    action = serializers.ChoiceField(
        choices=["pending", "under_review", "approved", "rejected"],
        write_only=True,
    )

    class Meta:
        fields = "__all__"
        model = DigitizationRequest
