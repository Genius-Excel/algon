from decouple import config
import os

from celery import Celery


os.environ.setdefault(
    "DJANGO_SETTINGS_MODULE",
    str(config("DJANGO_SETTINGS_MODULE", default="algon.settings")),
)

app = Celery("algon")

app.config_from_object("django.conf:settings", namespace="CELERY")

app.autodiscover_tasks()
