import random
import httpx
import string
import mailtrap as mt
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import timedelta
import cloudinary
import cloudinary.uploader
from core.models import AuditLog
from django.utils import timezone
from django.contrib.auth import get_user_model

User = get_user_model()

# from core.serializers import FileUploadSerializer


def generate_username(length=10):
    """This helper function generates a unique set of
    characters for the username with the combination of texts and numbers.

    Args:
      length (int): Lenght of the unique string to be generated.

     Returns:
        Uniquely generated string text as the username.
    """

    characters = string.ascii_letters + string.digits
    return "".join(random.choice(characters) for _ in range(length))


def generate_email_confirmation_token(user):
    """
    Generates an email confirmation token for a given user.

    This function creates a refresh token for the specified user and adds an
    'email_confirmation' flag to the token's payload. It then returns the
    access token as a string.

    Args:
       user (User): The user object for whom the email confirmation token is generated.

    Returns:
       str: The generated email confirmation access token.
    """
    refresh = RefreshToken.for_user(user)
    refresh.payload["email_confirmation"] = True
    refresh.set_exp(lifetime=timedelta(seconds=30))
    return str(refresh.access_token)


def send_email_with_html_template(
    template_file: str,
    template_context: dict,
    email_address: str,
    subject: str,
    sender_name: str,
):
    """
    Sends an email with an HTML template.
    Args:
       template_file (str): The filename of the HTML template to be used.
       template_context (dict): A dictionary containing the context variables to render the template.
       email_address (str): The recipient's email address.
       subject (str): The subject of the email.
       sender_name (str): The name of the sender.
    Returns:
       str: A message indicating the result of the email sending process.
    """

    try:
        template_loader = FileSystemLoader(searchpath=Path(__file__).parent)
        template_env = Environment(loader=template_loader)

        template = template_env.get_template(template_file)
        html_content = template.render(template_context)

    except Exception as e:
        return f"Error while loading or rendering the template: {e}"

    try:
        mail = mt.Mail(
            sender=mt.Address(
                email=settings.EMAIL_HOST_USER, name=sender_name
            ),
            to=[mt.Address(email=email_address)],
            subject=subject,
            text=None,
            html=html_content,
        )

        # Initialize the Mailtrap client and send the email
        client = mt.MailtrapClient(token=settings.SMTP_API_TOKEN)
        response = client.send(mail)

        if response["success"] == True:
            return "Email sent successfully!"
        else:
            return f"Failed to send email. {response['success']}"

    except Exception as e:
        return f"Error while sending email: {e}"


# Cloudinary Configuration
cloudinary.config(
    cloud_name=settings.CLOUDINARY_CLOUD_NAME,
    api_key=settings.CLOUDINARY_API_KEY,
    api_secret=settings.CLOUDINARY_API_SECRET,
)


def upload_file_to_cloudinary(file_name, folder: str = "uploads"):
    """
    Uploads a file to Cloudinary and returns the
    secure URL of the uploaded file.

    Args:
       file_name (str): The path to the file to be uploaded.

    Returns:
       str: The secure URL of the uploaded file if successful,
       or an error message if the upload fails.

    Raises:
       Exception: If there is an error during the upload process.
    """
    try:
        response = cloudinary.uploader.upload(file_name)
        secure_url = response.get("secure_url")
        if not secure_url:
            raise Exception("No secure_url returned from Cloudinary")
        return secure_url
    except Exception as e:
        raise Exception(f"Cloudinary upload failed: {str(e)}")


def create_audit_log(
    user,
    action_type: str,
    table_name: str,
    record_id=None,
    changes=None,
    description=None,
    request=None,
):
    """
    Create a new audit log entry.

    Args:
        user (User): The user performing the action.
        action_type (str): One of 'create', 'update', 'delete', 'login', 'logout', 'view'.
        table_name (str): The affected table/model name.
        record_id (uuid, optional): ID of the affected record.
        changes (dict, optional): Changed fields and values.
        description (str, optional): Summary or context for the log.
        request (HttpRequest, optional): Used to extract IP and User-Agent.
    """
    ip_address = None
    user_agent = None

    if request:
        ip_address = request.META.get("REMOTE_ADDR")
        user_agent = request.META.get("HTTP_USER_AGENT")

    AuditLog.objects.create(
        user=user,
        action_type=action_type,
        table_name=table_name,
        record_id=record_id,
        changes=changes,
        description=description,
        ip_address=ip_address,
        user_agent=user_agent,
        created_at=timezone.now(),
    )


def validate_nin_number(nin: str) -> bool:
    """This function validates the lenght of NIN
    number of an applicant.
    """
    if len(nin) == 11 and nin.isdigit():
        return True
    return False


def generate_random_id(
    length: int = 10,
    special_chars: bool = False,
    chars: list[str] | None = None,
    numeric: bool = True,
    prefix: str | None = None,
    use_separator: bool = False,
    separator: str = "-",
) -> str:
    """
    Generate a random string ID.

    Args:
        length (int): Length of string to be created.
        special_chars (bool): Whether to include punctuation symbols.
        chars (list[str] | None): Custom characters to use for generation.
        numeric (bool): Whether to include digits.
        prefix (str | None): Optional string prefix.
        use_separator (bool): Whether to separate prefix
        and random string with a symbol.
        separator (str): The separator to use if `use_separator` is True.

    Returns:
        str: Randomly generated string.
    """

    if chars:
        pool = "".join(chars)
    else:
        pool = string.ascii_letters
        if numeric:
            pool += string.digits
        if special_chars:
            pool += string.punctuation

    generated_string = "".join(random.choices(pool, k=length))

    if prefix:
        if use_separator:
            return f"{prefix}{separator}{generated_string}"
        return f"{prefix}{generated_string}"

    return generated_string


def get_request_info(request) -> dict[str, str | None]:
    """
    Retrieve information about incoming request

    Args:
        Request: HTTPRequest

    Returns
        Dict with the IP and user agent
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    ip = (
        x_forwarded_for.split(",")[0].strip()
        if x_forwarded_for
        else request.META.get("REMOTE_ADDR")
    )
    user_agent = request.META.get("HTTP_USER_AGENT", "")

    return {"ip": ip or None, "user_agent": user_agent or None}


# utils/permissions.py


def get_user_role(user):
    """
    Returns the role name of the user.
    """
    return getattr(user.role, "name", None)


# def handle_uploads(file, file_type, application_id=None):
#     """
#     Handles file uploads asynchronously via Celery.
#
#     Expects multipart/form-data with:
#         - file: the uploaded file
#         - file_type: the purpose (e.g., 'nin_slip', 'profile_photo')
#
#     Returns:
#         {
#             "task_id": "<celery_task_id>"
#         }
#     """
#     if not file or not file_type:
#         raise PermissionDenied("File and file_type are required.")
#     with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
#         for chunk in file.chunks():
#             tmp_file.write(chunk)
#         tmp_file_path = tmp_file.name
#     task = cloudinary_upload_task.delay(
#         tmp_file_path, file_type, application_id
#     )
#     return {"task_id": task.id}


def extract_payment_data(data):
    """extract payment data from request data"""
    payment_data = {
        "amount": data.get("amount"),
        "reference": data.get("reference"),
        "callback_url": data.get("callback_url"),
    }

    return payment_data


def paystack_url_generate(
    amount: int,
    email: str,
    reference: str,
    callback_url: str,
):
    """Generate a paystack payment url"""
    with httpx.Client() as client:
        url = "https://api.paystack.co/transaction/initialize"
        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
            "Content-Type": "application/json",
        }
        amount = int(float(amount))
        payload = {
            "amount": amount * 100,
            "email": email,
            "reference": reference,
            "callback_url": callback_url,
        }
        response = client.post(url, headers=headers, json=payload)

        return response


def extract_upload_file_data(request, files_needed: list[str], instance):
    """
    view to extract and send to cloudinary, the files attached in a request
    """
    from core.tasks import cloudinary_upload_task

    files = request.FILES
    [
        cloudinary_upload_task.delay(
            files.get(file).read(),
            file,
            str(instance.id),
            instance.__class__.__name__,
        )
        for file in files_needed
        if files.get(file)
    ]


def generate_report(report_type: str, user: User):
    from .models import CertificateApplication, DigitizationRequest

    if user.role == "lg_admin":
        pass
    return
