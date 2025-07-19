from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from core.models import EmailOTP
from unittest.mock import patch
from django.utils import timezone
import datetime

CREATE_USER_URL = reverse('user:create')
REQUEST_EMAIL_OTP_URL = reverse('user:request-email-otp')
VERIFY_EMAIL_OTP_URL = reverse('user:verify-email-otp')
JWT_TOKEN_URL = reverse('user:token')


def create_user(**params):
    """Helper function to create a user"""
    return get_user_model().objects.create_user(**params)


class EmailOTPApiTests(TestCase):
    """Test the email OTP API"""

    def setUp(self):
        self.client = APIClient()
        self.user = create_user(
            email='test@example.com',
            fname='Test',
            lname='User',
            phone='1234567890',
            password='testpass123',
        )
        # Login the user
        payload = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        tokens = self.client.post(JWT_TOKEN_URL, payload, format='json').data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")

    def test_request_otp_success(self):
        """Test requesting OTP for email change is successful"""
        payload = {'new_email': 'newemail@example.com'}

        with patch('user.views.generate_and_send_otp') as mock_send_otp:
            res = self.client.post(REQUEST_EMAIL_OTP_URL, payload)
            #create an OTP record to simulate sending email
            EmailOTP.objects.create(
                user=self.user,
                new_email=payload['new_email'],
                otp='123456'
            )

            mock_send_otp.assert_called_once_with(
                self.user,
                payload['new_email'],
                subject="Change Email OTP",
                purpose="change_email"
            )

        # Check response status and data
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn('message', res.data)


        # Check that an OTP record was created
        self.assertTrue(
            EmailOTP.objects.filter(
                user=self.user,
                new_email='newemail@example.com'
            ).exists()
        )

    def test_request_otp_same_email_and_verified(self):
        """Test requesting OTP with same email as verified current user email"""
        payload = {'new_email': 'test@example.com'}


        self.user.is_email_verified = True
        self.user.save()
        res = self.client.post(REQUEST_EMAIL_OTP_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('message', res.data)
        self.assertEqual(res.data['message'], 'Email is already verified')

    def test_request_otp_same_email_and_not_verified(self):
        """Test requesting OTP with same email as not verified current user email"""
        payload = {'new_email': 'test@example.com'}

        self.user.is_email_verified = False
        self.user.save()
        res = self.client.post(REQUEST_EMAIL_OTP_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn('message', res.data)
        self.assertEqual(res.data['message'], 'OTP sent to new E-Mail')

    def test_request_otp_email_in_use(self):
        """Test requesting OTP with email already in use by another user"""
        # Create another user with the email we want to change to
        create_user(
            email='inuse@example.com',
            fname='Another',
            lname='User',
            phone='9876543210',
            password='testpass123',
        )

        payload = {'new_email': 'inuse@example.com'}

        res = self.client.post(REQUEST_EMAIL_OTP_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', res.data)
        self.assertEqual(res.data['error'], 'Email already in use by another account')

    def test_request_otp_rate_limit(self):
        """Test rate limiting for OTP requests"""
        payload = {'new_email': 'newemail@example.com'}

        # Create 3 OTP records within the last hour
        one_hour_ago = timezone.now() - datetime.timedelta(hours=1) + datetime.timedelta(minutes=5)

        with patch('django.utils.timezone.now') as mock_now:
            mock_now.return_value = one_hour_ago
            for _ in range(3):
                EmailOTP.objects.create(
                    user=self.user,
                    new_email='newemail@example.com',
                    otp='123456'
                )

        res = self.client.post(REQUEST_EMAIL_OTP_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertIn('error', res.data)
        self.assertEqual(res.data['error'], 'Too many requests. Try again later.')

    def test_request_otp_invalid_email(self):
        """Test requesting OTP with invalid email format"""
        payload = {'new_email': 'invalid-email'}

        res = self.client.post(REQUEST_EMAIL_OTP_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_request_otp_unauthorized(self):
        """Test requesting OTP without authentication"""
        self.client.credentials()  # Clear credentials
        payload = {'new_email': 'newemail@example.com'}

        res = self.client.post(REQUEST_EMAIL_OTP_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)


class UserRegistrationTests(TestCase):
    """Test the user registration flow with email verification"""

    def setUp(self):
        self.client = APIClient()

    @patch('user.views.generate_and_send_otp')
    def test_create_user_sends_verification_email(self, mock_send_otp):
        """Test that creating a user sends a verification email"""
        payload = {
            'email': 'newuser@example.com',
            'fname': 'New',
            'lname': 'User',
            'phone': '1234567890',
            'password': 'testpass123',
            'password2': 'testpass123'
        }

        res = self.client.post(CREATE_USER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        user = get_user_model().objects.get(email=payload['email'])
        self.assertFalse(user.is_email_verified)
        mock_send_otp.assert_called_once_with(
            user,
            user.email,
            subject="Verify Your Email",
            purpose="registration"
        )

    @patch('user.views.generate_and_send_otp')
    def test_registration_verification_flow(self, mock_send_otp):
        """Test the complete registration and verification flow"""
        # 1. Register a new user
        payload = {
            'email': 'newuser@example.com',
            'fname': 'New',
            'lname': 'User',
            'phone': '1234567890',
            'password': 'testpass123',
            'password2': 'testpass123'
        }

        res = self.client.post(CREATE_USER_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        user = get_user_model().objects.get(email=payload['email'])
        self.assertFalse(user.is_email_verified)

        # 2. Create an OTP record (simulating the email sending)
        otp = '123456'
        EmailOTP.objects.create(
            user=user,
            new_email=user.email,
            otp=otp
        )

        # 3. Login to get token
        login_payload = {
            'email': 'newuser@example.com',
            'password': 'testpass123'
        }
        tokens = self.client.post(JWT_TOKEN_URL, login_payload).data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")

        # 4. Verify email with OTP
        verify_payload = {
            'new_email': user.email,
            'otp': otp
        }
        verify_res = self.client.post(VERIFY_EMAIL_OTP_URL, verify_payload)
        self.assertEqual(verify_res.status_code, status.HTTP_200_OK)

        # 5. Check that user is now verified
        user.refresh_from_db()
        self.assertTrue(user.is_email_verified)


class ConfirmEmailOTPTests(TestCase):
    """Test the email OTP confirmation API"""

    def setUp(self):
        self.client = APIClient()
        self.user = create_user(
            email='test@example.com',
            fname='Test',
            lname='User',
            phone='1234567890',
            password='testpass123',
        )
        # Login the user
        payload = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        tokens = self.client.post(JWT_TOKEN_URL, payload, format='json').data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")

        # Create a valid OTP
        self.new_email = 'newemail@example.com'
        self.otp = '123456'
        self.otp_record = EmailOTP.objects.create(
            user=self.user,
            new_email=self.new_email,
            otp=self.otp
        )

    def test_confirm_otp_success(self):
        """Test confirming OTP successfully changes email"""
        payload = {
            'new_email': self.new_email,
            'otp': self.otp
        }

        res = self.client.post(VERIFY_EMAIL_OTP_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn('success', res.data)

        # Refresh user from database
        self.user.refresh_from_db()

        # Check that email was updated
        self.assertEqual(self.user.email, self.new_email)
        self.assertTrue(self.user.is_email_verified)

        # Check that OTP record was deleted
        self.assertFalse(
            EmailOTP.objects.filter(
                user=self.user,
                new_email=self.new_email
            ).exists()
        )

    def test_confirm_otp_invalid_otp(self):
        """Test confirming with invalid OTP"""
        payload = {
            'new_email': self.new_email,
            'otp': '654321'  # Wrong OTP
        }

        res = self.client.post(VERIFY_EMAIL_OTP_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', res.data)

        # Refresh OTP record to check attempts increased
        self.otp_record.refresh_from_db()
        self.assertEqual(self.otp_record.attempts, 1)

        # Check email was not changed
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, 'test@example.com')

    def test_confirm_otp_expired(self):
        """Test confirming with expired OTP"""
        # Set OTP creation time to 11 minutes ago (expired)
        with patch('core.models.EmailOTP.is_otp_expired') as mock_expired:
            mock_expired.return_value = True

            payload = {
                'new_email': self.new_email,
                'otp': self.otp
            }

            res = self.client.post(VERIFY_EMAIL_OTP_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', res.data)
        self.assertEqual(res.data['error'], 'OTP expired')

        # Check email was not changed
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, 'test@example.com')

    def test_confirm_otp_too_many_attempts(self):
        """Test confirming OTP after too many failed attempts"""
        # Set attempts to max
        self.otp_record.attempts = 5
        self.otp_record.save()

        payload = {
            'new_email': self.new_email,
            'otp': self.otp
        }

        res = self.client.post(VERIFY_EMAIL_OTP_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertIn('error', res.data)
        self.assertEqual(res.data['error'], 'Too many failed attempts. Please request a new OTP.')

        # Check email was not changed
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, 'test@example.com')

    def test_confirm_otp_nonexistent_record(self):
        """Test confirming OTP with no matching record"""
        payload = {
            'new_email': 'nonexistent@example.com',
            'otp': self.otp
        }

        res = self.client.post(VERIFY_EMAIL_OTP_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', res.data)
        self.assertEqual(res.data['error'], 'Invalid OTP or Email')

    def test_confirm_otp_unauthorized(self):
        """Test confirming OTP without authentication"""
        self.client.credentials()  # Clear credentials
        payload = {
            'new_email': self.new_email,
            'otp': self.otp
        }

        res = self.client.post(VERIFY_EMAIL_OTP_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)