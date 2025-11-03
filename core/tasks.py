from celery import shared_task

from core.utils import upload_file_to_cloudinary


@shared_task(bind=True, max_retries=3)
def async_cloudinary_upload(self, file_bytes, file_name, file_type):
    from io import BytesIO

    try:
        file_obj = BytesIO(file_bytes)
        file_obj.name = file_name
        url = upload_file_to_cloudinary(file_obj)
        # url = response["secure_url"]

        # if file_type == "nin_slip":
        #     run_ocr_on_file.delay(url)

        return url
    except Exception as e:
        self.retry(exc=e, countdown=10)


# @shared_task()
# def run_ocr_on_file(self):
#     pass
