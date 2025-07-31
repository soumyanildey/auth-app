from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from decouple import config

class Command(BaseCommand):
    help = "Create default superuser using environment variables"

    def handle(self, *args, **kwargs):
        User = get_user_model()

        email = config("DJANGO_SUPERUSER_EMAIL")
        password = config("DJANGO_SUPERUSER_PASSWORD")

        # Optional fields if your create_superuser requires them
        fname = config("DJANGO_SUPERUSER_FIRSTNAME")
        lname = config("DJANGO_SUPERUSER_LASTNAME")
        phone = config("DJANGO_SUPERUSER_PHONE")

        if not User.objects.filter(email=email).exists():
            User.objects.create_superuser(
                email=email,
                password=password,
                fname=fname,
                lname=lname,
                phone=phone
            )
            self.stdout.write(self.style.SUCCESS("✅ Superuser created successfully."))
        else:
            self.stdout.write(self.style.WARNING("ℹ️ Superuser already exists."))
