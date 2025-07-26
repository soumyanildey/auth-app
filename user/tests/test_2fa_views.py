from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from unittest.mock import patch, MagicMock

User = get_user_model()


class Enable2FAViewTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            fname='Test',
            lname='User',
            phone='1234567890'
        )
        self.url = reverse('user:enable_2fa')

    def authenticate_user(self):
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

    @patch('user.views.qrcode.make')
    @patch('user.views.pyotp.random_base32')
    def test_enable_2fa_success(self, mock_secret, mock_qr):
        """Test successful 2FA enablement"""
        self.authenticate_user()

        mock_secret.return_value = 'TESTSECRET123456'
        mock_qr_instance = MagicMock()
        mock_qr.return_value = mock_qr_instance

        response = self.client.post(self.url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('qr_code', response.data)
        self.assertIn('message', response.data)
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_2fa_enabled)  # Not enabled until verified
        self.assertEqual(self.user.totp_secret, 'TESTSECRET123456')

    def test_enable_2fa_already_enabled(self):
        """Test enabling 2FA when already enabled"""
        self.authenticate_user()
        self.user.is_2fa_enabled = True
        self.user.save()

        response = self.client.post(self.url)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], '2FA already Enabled')

    def test_enable_2fa_unauthenticated(self):
        """Test enabling 2FA without authentication"""
        response = self.client.post(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_enable_2fa_invalid_token(self):
        """Test enabling 2FA with invalid token"""
        self.client.credentials(HTTP_AUTHORIZATION='Bearer invalid_token')

        response = self.client.post(self.url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_enable_2fa_wrong_http_method(self):
        """Test using wrong HTTP method"""
        self.authenticate_user()

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

        response = self.client.put(self.url)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @patch('user.views.qrcode.make')
    @patch('user.views.pyotp.random_base32')
    def test_enable_2fa_qr_generation_error(self, mock_secret, mock_qr):
        """Test QR code generation error handling"""
        self.authenticate_user()
        mock_secret.return_value = 'TESTSECRET123456'
        mock_qr.side_effect = Exception("QR generation failed")

        response = self.client.post(self.url)

        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.data['error'], 'Failed to enable 2FA')


class Verify2FAViewTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            fname='Test',
            lname='User',
            phone='1234567890'
        )
        # For most tests, we need a secret but 2FA not yet enabled (setup in progress)
        self.user.totp_secret = 'TESTSECRET123456'
        self.user.save()
        self.url = reverse('user:verify_2fa')

    def authenticate_user(self):
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

    @patch('user.views.pyotp.TOTP')
    def test_verify_2fa_success(self, mock_totp):
        """Test successful 2FA verification"""
        self.authenticate_user()

        mock_totp_instance = MagicMock()
        mock_totp.return_value = mock_totp_instance
        mock_totp_instance.verify.return_value = True

        response = self.client.post(self.url, {'otp': '123456'})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['success'], '2FA enabled successfully.')
        # Verify 2FA is now enabled
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_2fa_enabled)

    @patch('user.views.pyotp.TOTP')
    def test_verify_2fa_invalid_otp(self, mock_totp):
        """Test 2FA verification with invalid OTP"""
        self.authenticate_user()

        mock_totp_instance = MagicMock()
        mock_totp.return_value = mock_totp_instance
        mock_totp_instance.verify.return_value = False

        response = self.client.post(self.url, {'otp': '123456'})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid or expired OTP.')

    def test_verify_2fa_not_enabled(self):
        """Test 2FA verification when 2FA is not enabled"""
        self.authenticate_user()
        self.user.is_2fa_enabled = False
        self.user.totp_secret = None
        self.user.save()

        response = self.client.post(self.url, {'otp': '123456'})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], '2FA setup not initiated.')

    def test_verify_2fa_no_secret(self):
        """Test 2FA verification when no TOTP secret exists"""
        self.authenticate_user()
        self.user.totp_secret = None
        self.user.save()

        response = self.client.post(self.url, {'otp': '123456'})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], '2FA setup not initiated.')

    def test_verify_2fa_unauthenticated(self):
        """Test 2FA verification without authentication"""
        response = self.client.post(self.url, {'otp': '123456'})

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_verify_2fa_missing_otp(self):
        """Test 2FA verification with missing OTP"""
        self.authenticate_user()

        response = self.client.post(self.url, {})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid Credentials')

    def test_verify_2fa_empty_otp(self):
        """Test 2FA verification with empty OTP"""
        self.authenticate_user()

        response = self.client.post(self.url, {'otp': ''})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid Credentials')

    def test_verify_2fa_wrong_length_otp(self):
        """Test 2FA verification with wrong length OTP"""
        self.authenticate_user()

        response = self.client.post(self.url, {'otp': '12345'})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid Credentials')

    def test_verify_2fa_wrong_http_method(self):
        """Test using wrong HTTP method"""
        self.authenticate_user()

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

        response = self.client.put(self.url)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

        # Too short
        response = self.client.post(self.url, {'otp': '123'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Too long
        response = self.client.post(self.url, {'otp': '1234567890'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_verify_2fa_expired_otp(self):
        """Test 2FA verification with expired OTP"""
        self.authenticate_user()

        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = False  # Expired OTP

            response = self.client.post(self.url, {'otp': '123456'})

            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertEqual(response.data['error'], 'Invalid or expired OTP.')

    def test_verify_2fa_wrong_http_method(self):
        """Test using wrong HTTP method"""
        self.authenticate_user()

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

        response = self.client.put(self.url)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_verify_2fa_with_valid_window(self):
        """Test 2FA verification with valid window parameter"""
        self.authenticate_user()

        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = True

            response = self.client.post(self.url, {'otp': '123456'})

            mock_totp_instance.verify.assert_called_once_with('123456', valid_window=1)

    def test_verify_2fa_special_characters_in_otp(self):
        """Test 2FA verification with special characters in OTP"""
        self.authenticate_user()

        response = self.client.post(self.url, {'otp': '12@#$6'})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid or expired OTP.')

    def test_verify_2fa_unicode_characters(self):
        """Test 2FA verification with unicode characters"""
        self.authenticate_user()

        response = self.client.post(self.url, {'otp': '12345ñ'})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid or expired OTP.')

    def test_verify_2fa_sql_injection_attempt(self):
        """Test 2FA verification with SQL injection attempt"""
        self.authenticate_user()

        response = self.client.post(self.url, {'otp': "'; DROP TABLE users; --"})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid Credentials')

    def test_verify_2fa_xss_attempt(self):
        """Test 2FA verification with XSS attempt"""
        self.authenticate_user()

        response = self.client.post(self.url, {'otp': '<script>alert("xss")</script>'})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid Credentials')


class TwoFAIntegrationTestCase(TestCase):
    """Integration tests for complete 2FA flow"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='integration@example.com',
            password='testpass123',
            fname='Integration',
            lname='Test'
        )
        self.enable_url = reverse('user:enable_2fa')
        self.verify_url = reverse('user:verify_2fa')

    def authenticate_user(self):
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

    def test_complete_2fa_flow(self):
        """Test complete 2FA enablement and verification flow"""
        self.authenticate_user()

        # Step 1: Enable 2FA (generates QR, saves secret, but doesn't enable yet)
        with patch('qrcode.make') as mock_qr, patch('pyotp.random_base32') as mock_secret:
            mock_secret.return_value = 'TESTSECRET123456'
            mock_qr_instance = MagicMock()
            mock_qr.return_value = mock_qr_instance

            enable_response = self.client.post(self.enable_url)

            self.assertEqual(enable_response.status_code, status.HTTP_200_OK)
            self.user.refresh_from_db()
            self.assertFalse(self.user.is_2fa_enabled)  # Not enabled until verified
            self.assertEqual(self.user.totp_secret, 'TESTSECRET123456')

        # Step 2: Verify 2FA (this actually enables 2FA)
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = True

            verify_response = self.client.post(self.verify_url, {'otp': '123456'})

            self.assertEqual(verify_response.status_code, status.HTTP_200_OK)
            self.user.refresh_from_db()
            self.assertTrue(self.user.is_2fa_enabled)  # Now it's enabled

    def test_multiple_users_2fa_isolation(self):
        """Test that 2FA settings are isolated between users"""
        user2 = User.objects.create_user(
            email='user2@example.com',
            password='testpass123',
            fname='User',
            lname='Two'
        )

        # Enable 2FA for first user
        self.authenticate_user()
        with patch('qrcode.make'), patch('pyotp.random_base32', return_value='SECRET1'):
            self.client.post(self.enable_url)
        # Complete 2FA setup
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = True
            self.client.post(self.verify_url, {'otp': '123456'})

        # Switch to second user
        refresh2 = RefreshToken.for_user(user2)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh2.access_token}')

        # Second user should not have 2FA enabled
        response = self.client.post(self.verify_url, {'otp': '123456'})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], '2FA setup not initiated.')

    def test_2fa_state_persistence(self):
        """Test that 2FA state persists across sessions"""
        self.authenticate_user()

        # Enable 2FA
        with patch('qrcode.make'), patch('pyotp.random_base32', return_value='PERSISTENT'):
            self.client.post(self.enable_url)
        # Complete 2FA setup
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = True
            self.client.post(self.verify_url, {'otp': '123456'})

        # Create new session
        new_client = APIClient()
        refresh = RefreshToken.for_user(self.user)
        new_client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        # Try to enable 2FA again - should fail
        response = new_client.post(self.enable_url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], '2FA already Enabled')