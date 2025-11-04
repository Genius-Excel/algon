from celery import shared_task

from core.utils import upload_file_to_cloudinary


@shared_task(bind=True, max_retries=3)
def cloudinary_upload_task(self, file_path, file_type):

    try:
        url = upload_file_to_cloudinary(file_path)
        # url = response["secure_url"]

        # if file_type == "nin_slip":
        #     run_ocr_on_file.delay(url)

        return url
    except Exception as e:
        self.retry(exc=e, countdown=10)


# @shared_task()
# def run_ocr_on_file(self):
#     pass
