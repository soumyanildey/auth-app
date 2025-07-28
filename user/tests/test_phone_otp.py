from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.test import APIClient
from rest_framework import status
from django.urls import reverse
import random
from django.conf import settings

User = get_user_model()

class PhoneOTPTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.phone = '15005550006'
        self.email = 'test@example.com'
        self.fname = 'test'
        self.lname = 'user'
        self.otp = str(random.randint(100000, 999999))

        self.user = User.objects.create_user(email=self.email, fname=self.fname,lname=self.lname, phone=self.phone, password='testpass123')
        self.verify_url = reverse('user:verify-sms-otp')
        self.send_url = reverse('user:request-sms-otp')

        # Authenticate user (JWT alternative provided below)
        # self.client.force_authenticate(user=self.user)

        # JWT alternative:
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {str(refresh.access_token)}')

    def tearDown(self):
        cache.clear()

    # -----------------------------
    # OTP Sending Tests
    # -----------------------------
    def test_send_otp_successfully(self):
        response = self.client.post(self.send_url, {'phone': self.phone})
        self.assertEqual(response.status_code, status.HTTP_200_OK, response.data)
        self.assertTrue(cache.get(f'otp_{self.phone}'))

    def test_send_otp_with_missing_phone(self):
        response = self.client.post(self.send_url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_send_otp_unregistered_phone(self):
        response = self.client.post(self.send_url, {'phone': '8888888888'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_send_otp_blocked_user(self):
        self.user.is_blocked = True
        self.user.save()
        response = self.client.post(self.send_url, {'phone': self.phone})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_send_otp_within_cooldown(self):
        cache.set(f'sms_cooldown_{self.phone}', True, timeout=90)
        response = self.client.post(self.send_url, {'phone': self.phone})
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    # -----------------------------
    # OTP Verification Tests
    # -----------------------------
    def test_verify_valid_otp(self):
        cache.set(f'otp_{self.phone}', self.otp, timeout=300)
        response = self.client.post(self.verify_url, {'phone': self.phone, 'otp': self.otp})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_phone_verified)

    def test_verify_expired_otp(self):
        # OTP not cached
        response = self.client.post(self.verify_url, {'phone': self.phone, 'otp': self.otp})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_verify_incorrect_otp(self):
        cache.set(f'otp_{self.phone}', self.otp, timeout=300)
        response = self.client.post(self.verify_url, {'phone': self.phone, 'otp': '000000'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_verify_missing_otp(self):
        cache.set(f'otp_{self.phone}', self.otp, timeout=300)
        response = self.client.post(self.verify_url, {'phone': self.phone})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_verify_invalid_otp_format(self):
        cache.set(f'otp_{self.phone}', self.otp, timeout=300)
        response = self.client.post(self.verify_url, {'phone': self.phone, 'otp': 'abc123'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_verify_invalid_phone_format(self):
        cache.set('otp_abc', self.otp, timeout=300)
        response = self.client.post(self.verify_url, {'phone': 'abc', 'otp': self.otp})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_verify_user_mismatch(self):
        cache.set(f'otp_{self.phone}', self.otp, timeout=300)
        other_user = User.objects.create_user(email='new@example.com',fname='test',lname='user',phone='8888888888', password='otherpass')
        self.client.force_authenticate(user=other_user)
        response = self.client.post(self.verify_url, {'phone': self.phone, 'otp': self.otp})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_verify_blocked_user(self):
        self.user.is_blocked = True
        self.user.save()
        cache.set(f'otp_{self.phone}', self.otp, timeout=300)
        response = self.client.post(self.verify_url, {'phone': self.phone, 'otp': self.otp})
        self.assertEqual(response.status_code, status.HTTP_423_LOCKED)

    def test_verify_unauthenticated(self):
        self.client.force_authenticate(user=None)
        cache.set(f'otp_{self.phone}', self.otp, timeout=300)
        response = self.client.post(self.verify_url, {'phone': self.phone, 'otp': self.otp})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
