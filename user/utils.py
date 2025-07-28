from django.core.mail import send_mail
from django.conf import settings
from django.db import transaction
from core.models import EmailOTP
import secrets
from twilio.rest import Client
from django.core.cache import cache
import random


def generate_and_send_otp(user, new_email, subject="Verify Email", purpose="verification"):
    otp = secrets.randbelow(900000) + 100000
    EmailOTP.objects.filter(user=user, new_email=new_email).delete()

    EmailOTP.objects.create(user=user, new_email=new_email, otp=str(otp))

    send_mail(
        subject=subject,
        message=f"Your OTP for {purpose.replace('_', ' ')} is {otp}. It will expire in 10 minutes.",
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[new_email],
        fail_silently=False,
    )


def validate_otp(user, new_email, otp_input):
    try:
        with transaction.atomic():
            record = EmailOTP.objects.select_for_update().filter(
                user=user, new_email=new_email
            ).order_by("-created_at").first()

            if not record:
                return False, "Invalid OTP or Email"

            if record.attempts >= 5:
                return False, "Too many failed attempts. Please request a new OTP."

            if record.is_otp_expired():
                return False, "OTP expired"

            if str(record.otp) != str(otp_input):
                record.attempts += 1
                record.save()
                return False, "Invalid OTP"

            return True, record
    except EmailOTP.DoesNotExist:
        return False, "Invalid OTP or Email"


def send_otp_via_sms(phone_number: str, otp: str) -> str:
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_TEST_AUTH_TOKEN)

    message = client.messages.create(
        body = f'''\nYour Verification Code is {otp}\nIt is valid for 5 minutes.\n''',
        from_=settings.TWILIO_TEST_NUMBER,
        to=phone_number
    )

    return message.sid


def generate_and_send_sms_otp(phone_number):
    COOLDOWN_KEY = f"sms_cooldown_{phone_number}"

    if cache.get(COOLDOWN_KEY):
        raise Exception ("OTP already sent. Try after some time.")

    otp = str(random.randint(100000,999999))

    cache.set(f"otp_{phone_number}",otp, timeout=300)

    cache.set(COOLDOWN_KEY, True, timeout=90)

    send_otp_via_sms(phone_number,otp)

    return otp
