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

    def test_login_with_2fa_enabled_no_otp(self):
        """Test login for user with 2FA enabled without OTP"""
        self.user.is_2fa_enabled = True
        self.user.totp_secret = 'TESTSECRET123456'
        self.user.save()

        response = self.client.post(self.url, {
            'email': 'test@example.com',
            'password': 'testpass123'
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['requires_2fa'])
        self.assertEqual(response.data['message'], '2FA verification required')
        self.assertNotIn('access', response.data)
        self.assertNotIn('refresh', response.data)

    def test_unified_login_with_2fa_and_otp(self):
        """Test unified login with 2FA and OTP in single request"""
        self.user.is_2fa_enabled = True
        self.user.totp_secret = 'TESTSECRET123456'
        self.user.save()

        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = True

            response = self.client.post(self.url, {
                'email': 'test@example.com',
                'password': 'testpass123',
                'otp': '123456'
            })

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertIn('access', response.data)
            self.assertIn('refresh', response.data)

    def test_unified_login_with_invalid_otp(self):
        """Test unified login with invalid OTP"""
        self.user.is_2fa_enabled = True
        self.user.totp_secret = 'TESTSECRET123456'
        self.user.save()

        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = False

            response = self.client.post(self.url, {
                'email': 'test@example.com',
                'password': 'testpass123',
                'otp': '123456'
            })

            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

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


class UnifiedLogin2FATestCase(TestCase):
    """Test cases for unified login with 2FA"""

    def setUp(self):
        self.client = APIClient()
        self.url = reverse('user:token')
        self.user = User.objects.create_user(
            email='test2fa@example.com',
            password='testpass123',
            fname='Test',
            lname='User',
            is_2fa_enabled=True,
            totp_secret='TESTSECRET123456'
        )

    def test_otp_validation_numeric_only(self):
        """Test OTP validation accepts only numeric values"""
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = False

            response = self.client.post(self.url, {
                'email': 'test2fa@example.com',
                'password': 'testpass123',
                'otp': 'abcdef'
            })

            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_otp_validation_length(self):
        """Test OTP validation for proper length"""
        # Test short OTP gets padded
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = True

            response = self.client.post(self.url, {
                'email': 'test2fa@example.com',
                'password': 'testpass123',
                'otp': '123'  # Should be padded to 000123
            })

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            mock_totp_instance.verify.assert_called_with('000123', valid_window=1)

    def test_empty_otp_requires_2fa_response(self):
        """Test empty OTP returns requires_2fa response"""
        response = self.client.post(self.url, {
            'email': 'test2fa@example.com',
            'password': 'testpass123',
            'otp': ''
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['requires_2fa'])
        self.assertEqual(response.data['message'], '2FA verification required')




class Complete2FALoginFlowTestCase(TestCase):
    """Integration tests for complete 2FA login flow"""

    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse('user:token')
        
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

    def test_complete_flow_with_2fa_unified(self):
        """Test unified login flow for user with 2FA"""
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = True

            response = self.client.post(self.login_url, {
                'email': 'with2fa@example.com',
                'password': 'testpass123',
                'otp': '123456'
            })

            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertIn('access', response.data)
            self.assertIn('refresh', response.data)

    def test_complete_flow_with_2fa_two_step(self):
        """Test two-step login flow for user with 2FA"""
        # Step 1: Initial login without OTP
        response = self.client.post(self.login_url, {
            'email': 'with2fa@example.com',
            'password': 'testpass123'
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['requires_2fa'])
        self.assertEqual(response.data['message'], '2FA verification required')

        # Step 2: Complete login with OTP
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = True

            response = self.client.post(self.login_url, {
                'email': 'with2fa@example.com',
                'password': 'testpass123',
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
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = False

            response = self.client.post(self.login_url, {
                'email': 'with2fa@example.com',
                'password': 'testpass123',
                'otp': '123456'
            })

            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_multiple_users_isolation(self):
        """Test that 2FA login is isolated between users"""
        other_user = User.objects.create_user(
            email='other@example.com',
            password='testpass123',
            fname='Other',
            lname='User',
            is_2fa_enabled=True,
            totp_secret='OTHERSECRET123'
        )

        # Test each user can login independently
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = True

            # First user login
            response1 = self.client.post(self.login_url, {
                'email': 'with2fa@example.com',
                'password': 'testpass123',
                'otp': '123456'
            })
            self.assertEqual(response1.status_code, status.HTTP_200_OK)

            # Second user login
            response2 = self.client.post(self.login_url, {
                'email': 'other@example.com',
                'password': 'testpass123',
                'otp': '123456'
            })
            self.assertEqual(response2.status_code, status.HTTP_200_OK)

    def test_token_validity_after_2fa_login(self):
        """Test that tokens work correctly after 2FA login"""
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = True

            response = self.client.post(self.login_url, {
                'email': 'with2fa@example.com',
                'password': 'testpass123',
                'otp': '123456'
            })

            access_token = response.data['access']

        # Use token to access protected endpoint
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        response = self.client.get(reverse('user:me'))
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'with2fa@example.com')