from django.test import TestCase
from django.core import mail
from django.utils import timezone
from unittest.mock import patch
from datetime import timedelta
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase
from core.models import EmailOTP
from user.utils import generate_and_send_otp, validate_otp


class EmailOTPTests(APITestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email='old@example.com',
            password='pass1234'
        )
        self.new_email = 'new@example.com'

    def test_generate_and_send_otp_creates_otp(self):
        generate_and_send_otp(self.user, self.new_email)

        otp_obj = EmailOTP.objects.get(user=self.user, new_email=self.new_email)
        self.assertTrue(otp_obj.otp)
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn(self.new_email, mail.outbox[0].to)

    def test_generate_and_send_otp_deletes_previous(self):
        EmailOTP.objects.create(user=self.user, new_email=self.new_email, otp='123456')
        generate_and_send_otp(self.user, self.new_email)
        self.assertEqual(EmailOTP.objects.filter(user=self.user, new_email=self.new_email).count(), 1)

    def test_validate_otp_success(self):
        generate_and_send_otp(self.user, self.new_email)
        otp_obj = EmailOTP.objects.get(user=self.user, new_email=self.new_email)
        is_valid, result = validate_otp(self.user, self.new_email, otp_obj.otp)
        self.assertTrue(is_valid)
        self.assertEqual(result, otp_obj)

    def test_validate_otp_incorrect(self):
        generate_and_send_otp(self.user, self.new_email)
        is_valid, msg = validate_otp(self.user, self.new_email, 'wrongotp')
        self.assertFalse(is_valid)
        self.assertEqual(msg, "Invalid OTP")

    def test_validate_otp_too_many_attempts(self):
        EmailOTP.objects.create(user=self.user, new_email=self.new_email, otp='123456', attempts=5)
        is_valid, msg = validate_otp(self.user, self.new_email, '123456')
        self.assertFalse(is_valid)
        self.assertEqual(msg, "Too many failed attempts. Please request a new OTP.")

    def test_validate_otp_expired(self):
        otp_obj = EmailOTP.objects.create(user=self.user, new_email=self.new_email, otp='123456')
        otp_obj.created_at = timezone.now() - timedelta(minutes=11)
        otp_obj.save()

        with patch.object(EmailOTP, 'is_otp_expired', return_value=True):
            is_valid, msg = validate_otp(self.user, self.new_email, '123456')
            self.assertFalse(is_valid)
            self.assertEqual(msg, "OTP expired")

    def test_validate_otp_missing_record(self):
        is_valid, msg = validate_otp(self.user, self.new_email, '123456')
        self.assertFalse(is_valid)
        self.assertEqual(msg, "Invalid OTP or Email")