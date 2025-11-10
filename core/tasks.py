from django.db.models import ObjectDoesNotExist
from celery import shared_task
import logging

from core.models import ApplicationFieldResponse
from core.utils import upload_file_to_cloudinary

logger = logging.getLogger(__name__)


@shared_task(bind=True)
def cloudinary_upload_task(self, file_bytes, file_type, application_id, model):
    """
    Uploads a file to Cloudinary and updates the corresponding CertificateApplication field.

    Args:
        file_bytes (bytes): File content read from request.FILES
        file_type (str): Field name in CertificateApplication to update ('nin_slip', 'profile_photo', etc.)
        application_id (str): UUID of the CertificateApplication instance
    """
    from .models import CertificateApplication, DigitizationRequest

    allowed_models = {
        "CertificateApplication": CertificateApplication,
        "DigitizationRequest": DigitizationRequest,
        "ApplicationFieldResponse": ApplicationFieldResponse,
    }
    selected_model = allowed_models.get(model, None)
    if not selected_model:
        return
    try:
        logger.info("starting")
        file_url = upload_file_to_cloudinary(file_bytes)

        if not file_url:
            raise Exception("Cloudinary did not return a secure_url")
        logger.info("this is the file_url: ", file_url)

        # Update the model
        application = selected_model.objects.get(id=application_id)
        setattr(application, file_type, file_url)
        application.save()

        return {"status": "success", "file_url": file_url}

    except ObjectDoesNotExist:
        return {"status": "error", "message": "Application not found"}
    except Exception as e:
        self.retry(exc=e, countdown=10, max_retries=3)
        return {"status": "error", "message": str(e)}


# @shared_task()
# def run_ocr_on_file(self):
#     pass
