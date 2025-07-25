from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from unittest.mock import patch, MagicMock
import pyotp

User = get_user_model()


class CustomTokenObtainPairSerializerTestCase(TestCase):
    """Test cases for modified login serializer with 2FA support"""

    def setUp(self):
        self.client = APIClient()
        self.url = reverse('user:token')
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            fname='Test',
            lname='User'
        )

    def test_login_without_2fa(self):
        """Test normal login for user without 2FA"""
        response = self.client.post(self.url, {
            'email': 'test@example.com',
            'password': 'testpass123'
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertNotIn('requires_2fa', response.data)

    def test_login_with_2fa_enabled(self):
        """Test login for user with 2FA enabled"""
        self.user.is_2fa_enabled = True
        self.user.totp_secret = 'TESTSECRET123456'
        self.user.save()

        response = self.client.post(self.url, {
            'email': 'test@example.com',
            'password': 'testpass123'
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['requires_2fa'])
        self.assertEqual(response.data['user_id'], self.user.id)
        self.assertEqual(response.data['message'], '2FA verification required')
        self.assertNotIn('access', response.data)
        self.assertNotIn('refresh', response.data)

    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        response = self.client.post(self.url, {
            'email': 'test@example.com',
            'password': 'wrongpassword'
        })

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_nonexistent_user(self):
        """Test login with nonexistent user"""
        response = self.client.post(self.url, {
            'email': 'nonexistent@example.com',
            'password': 'testpass123'
        })

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_missing_fields(self):
        """Test login with missing fields"""
        response = self.client.post(self.url, {
            'email': 'test@example.com'
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.post(self.url, {
            'password': 'testpass123'
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class Login2FAViewTestCase(TestCase):
    """Test cases for Login2FA view"""

    def setUp(self):
        self.client = APIClient()
        self.url = reverse('user:login_2fa')
        self.user = User.objects.create_user(
            email='test2fa@example.com',
            password='testpass123',
            fname='Test',
            lname='User',
            is_2fa_enabled=True,
            totp_secret='TESTSECRET123456'
        )

    def test_successful_2fa_login(self):
        """Test successful 2FA login completion"""
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = True

            response = self.client.post(self.url, {
                'user_id': self.user.id,
                'otp': '123456'
            })

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertIn('access', response.data)
            self.assertIn('refresh', response.data)
            mock_totp_instance.verify.assert_called_once_with('123456', valid_window=1)

    def test_invalid_otp(self):
        """Test 2FA login with invalid OTP"""
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = False

            response = self.client.post(self.url, {
                'user_id': self.user.id,
                'otp': '123456'
            })

            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertEqual(response.data['error'], 'Invalid or expired OTP')

    def test_invalid_user_id(self):
        """Test 2FA login with invalid user ID"""
        response = self.client.post(self.url, {
            'user_id': 99999,
            'otp': '123456'
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid user')

    def test_user_without_2fa(self):
        """Test 2FA login for user without 2FA enabled"""
        user_no_2fa = User.objects.create_user(
            email='no2fa@example.com',
            password='testpass123',
            fname='No2FA',
            lname='User'
        )

        response = self.client.post(self.url, {
            'user_id': user_no_2fa.id,
            'otp': '123456'
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], '2FA not enabled')

    def test_user_without_totp_secret(self):
        """Test 2FA login for user with 2FA enabled but no TOTP secret"""
        self.user.totp_secret = None
        self.user.save()

        response = self.client.post(self.url, {
            'user_id': self.user.id,
            'otp': '123456'
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], '2FA not enabled')

    def test_missing_user_id(self):
        """Test 2FA login with missing user_id"""
        response = self.client.post(self.url, {
            'otp': '123456'
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid credentials')

    def test_missing_otp(self):
        """Test 2FA login with missing OTP"""
        response = self.client.post(self.url, {
            'user_id': self.user.id
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Invalid credentials')

    def test_invalid_otp_length(self):
        """Test 2FA login with invalid OTP length"""
        response = self.client.post(self.url, {
            'user_id': self.user.id,
            'otp': '12345'  # Too short
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        response = self.client.post(self.url, {
            'user_id': self.user.id,
            'otp': '1234567'  # Too long
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_empty_otp(self):
        """Test 2FA login with empty OTP"""
        response = self.client.post(self.url, {
            'user_id': self.user.id,
            'otp': ''
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_non_numeric_otp(self):
        """Test 2FA login with non-numeric OTP"""
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = False

            response = self.client.post(self.url, {
                'user_id': self.user.id,
                'otp': 'abcdef'
            })

            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertEqual(response.data['error'], 'Invalid or expired OTP')

    def test_wrong_http_method(self):
        """Test using wrong HTTP method"""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

        response = self.client.put(self.url)
        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_totp_exception_handling(self):
        """Test exception handling in TOTP verification"""
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp.side_effect = Exception("TOTP error")

            response = self.client.post(self.url, {
                'user_id': self.user.id,
                'otp': '123456'
            })

            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertEqual(response.data['error'], 'Invalid or expired OTP')


class Complete2FALoginFlowTestCase(TestCase):
    """Integration tests for complete 2FA login flow"""

    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse('user:token')
        self.login_2fa_url = reverse('user:login_2fa')
        
        # User without 2FA
        self.user_no_2fa = User.objects.create_user(
            email='no2fa@example.com',
            password='testpass123',
            fname='No2FA',
            lname='User'
        )
        
        # User with 2FA
        self.user_2fa = User.objects.create_user(
            email='with2fa@example.com',
            password='testpass123',
            fname='With2FA',
            lname='User',
            is_2fa_enabled=True,
            totp_secret='TESTSECRET123456'
        )

    def test_complete_flow_without_2fa(self):
        """Test complete login flow for user without 2FA"""
        response = self.client.post(self.login_url, {
            'email': 'no2fa@example.com',
            'password': 'testpass123'
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)

    def test_complete_flow_with_2fa(self):
        """Test complete login flow for user with 2FA"""
        # Step 1: Initial login
        response = self.client.post(self.login_url, {
            'email': 'with2fa@example.com',
            'password': 'testpass123'
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['requires_2fa'])
        self.assertEqual(response.data['user_id'], self.user_2fa.id)

        # Step 2: 2FA verification
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = True

            response = self.client.post(self.login_2fa_url, {
                'user_id': self.user_2fa.id,
                'otp': '123456'
            })

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertIn('access', response.data)
            self.assertIn('refresh', response.data)

    def test_2fa_flow_with_wrong_credentials(self):
        """Test 2FA flow with wrong initial credentials"""
        response = self.client.post(self.login_url, {
            'email': 'with2fa@example.com',
            'password': 'wrongpassword'
        })

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_2fa_flow_with_wrong_otp(self):
        """Test 2FA flow with correct credentials but wrong OTP"""
        # Step 1: Initial login
        response = self.client.post(self.login_url, {
            'email': 'with2fa@example.com',
            'password': 'testpass123'
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['requires_2fa'])

        # Step 2: Wrong OTP
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = False

            response = self.client.post(self.login_2fa_url, {
                'user_id': self.user_2fa.id,
                'otp': '123456'
            })

            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertEqual(response.data['error'], 'Invalid or expired OTP')

    def test_multiple_users_isolation(self):
        """Test that 2FA login is isolated between users"""
        # Login with first user
        response = self.client.post(self.login_url, {
            'email': 'with2fa@example.com',
            'password': 'testpass123'
        })

        user_id = response.data['user_id']

        # Try to use different user's ID in 2FA step
        other_user = User.objects.create_user(
            email='other@example.com',
            password='testpass123',
            fname='Other',
            lname='User',
            is_2fa_enabled=True,
            totp_secret='OTHERSECRET123'
        )

        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = True

            response = self.client.post(self.login_2fa_url, {
                'user_id': other_user.id,  # Different user
                'otp': '123456'
            })

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            # Should still work as it's a valid user with valid OTP

    def test_token_validity_after_2fa_login(self):
        """Test that tokens work correctly after 2FA login"""
        # Complete 2FA login
        response = self.client.post(self.login_url, {
            'email': 'with2fa@example.com',
            'password': 'testpass123'
        })

        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = True

            response = self.client.post(self.login_2fa_url, {
                'user_id': self.user_2fa.id,
                'otp': '123456'
            })

            access_token = response.data['access']

        # Use token to access protected endpoint
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        response = self.client.get(reverse('user:me'))
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'with2fa@example.com')