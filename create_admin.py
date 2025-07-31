# core/management/commands/create_admin.py
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from decouple import config

class Command(BaseCommand):
    help = "Create default superuser using environment variables"

    def handle(self, *args, **kwargs):
        User = get_user_model()
        username = config("DJANGO_SUPERUSER_USERNAME")
        email = config("DJANGO_SUPERUSER_EMAIL")
        password = config("DJANGO_SUPERUSER_PASSWORD")

        if not User.objects.filter(username=username).exists():
            User.objects.create_superuser(username=username, email=email, password=password)
            self.stdout.write(self.style.SUCCESS("✅ Superuser created successfully."))
        else:
            self.stdout.write(self.style.WARNING("ℹ️ Superuser already exists."))
