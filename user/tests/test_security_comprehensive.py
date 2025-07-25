from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from unittest.mock import patch, MagicMock
from core.models import EmailOTP, PasswordHistory
from django.utils import timezone
import datetime

User = get_user_model()


@override_settings(
    REST_FRAMEWORK={
        'DEFAULT_THROTTLE_CLASSES': [],
        'DEFAULT_THROTTLE_RATES': {},
    }
)
class SecurityTestCase(TestCase):
    """Comprehensive security tests covering all major features"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            fname='Test',
            lname='User',
            phone='1234567890'
        )
        self.admin = User.objects.create_user(
            email='admin@example.com',
            password='adminpass123',
            fname='Admin',
            lname='User',
            phone='1234567891',
            role='admin'
        )
        self.login_url = reverse('user:token')
        self.unblock_url = reverse('user:unblock_user')

    # ACCOUNT LOCKOUT TESTS
    def test_account_lockout_flow(self):
        """Test complete account lockout and recovery flow"""
        # Test failed attempts increment
        response = self.client.post(self.login_url, {
            'email': 'test@example.com',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 1)

        # Test account blocked after 5 attempts
        for i in range(4):  # 4 more attempts (total 5)
            self.client.post(self.login_url, {
                'email': 'test@example.com',
                'password': 'wrongpassword'
            })

        self.user.refresh_from_db()
        self.assertTrue(self.user.is_blocked)
        self.assertEqual(self.user.failed_login_attempts, 5)

        # Test blocked account cannot login
        response = self.client.post(self.login_url, {
            'email': 'test@example.com',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, status.HTTP_423_LOCKED)

        # Test admin can unblock
        refresh = RefreshToken.for_user(self.admin)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        
        response = self.client.post(self.unblock_url, {
            'email': 'test@example.com'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Test successful login after unblock
        self.client.credentials()
        response = self.client.post(self.login_url, {
            'email': 'test@example.com',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_account_states(self):
        """Test different account states"""
        # Test inactive account
        self.user.is_active = False
        self.user.save()
        response = self.client.post(self.login_url, {
            'email': 'test@example.com',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Reset for next test
        self.user.is_active = True
        self.user.save()

        # Test successful login resets failed attempts
        self.user.failed_login_attempts = 3
        self.user.save()
        response = self.client.post(self.login_url, {
            'email': 'test@example.com',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 0)

    # 2FA TESTS
    def test_2fa_complete_flow(self):
        """Test complete 2FA flow"""
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        
        # Enable 2FA
        enable_2fa_url = reverse('user:enable_2fa')
        with patch('qrcode.make'), patch('pyotp.random_base32', return_value='SECRET'):
            response = self.client.post(enable_2fa_url)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertIn('qr_code', response.data)

        # Test login requires 2FA
        self.client.credentials()
        response = self.client.post(self.login_url, {
            'email': 'test@example.com',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['requires_2fa'])

        # Test 2FA verification
        verify_2fa_url = reverse('user:verify_2fa')
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = True
            
            response = self.client.post(verify_2fa_url, {'otp': '123456'})
            self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Test 2FA login completion
        login_2fa_url = reverse('user:login_2fa')
        self.client.credentials()
        
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp.return_value = mock_totp_instance
            mock_totp_instance.verify.return_value = True
            
            response = self.client.post(login_2fa_url, {
                'user_id': self.user.id,
                'otp': '123456'
            })
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertIn('access', response.data)

    # PASSWORD SECURITY TESTS
    def test_password_security_flow(self):
        """Test password change and history"""
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        
        # Test password change
        change_url = reverse('user:passchange')
        response = self.client.post(change_url, {
            'old_password': 'testpass123',
            'new_password': 'newpass123'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Test password history created
        history_count = PasswordHistory.objects.filter(user=self.user).count()
        self.assertGreaterEqual(history_count, 1)

        # Test password reuse prevention
        response = self.client.post(change_url, {
            'old_password': 'newpass123',
            'new_password': 'testpass123'
        })
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('recent ones', response.data['error'])

    # EMAIL SECURITY TESTS
    def test_email_change_security(self):
        """Test email change with OTP"""
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        
        # Request email change OTP
        request_otp_url = reverse('user:request-email-otp')
        response = self.client.post(request_otp_url, {
            'new_email': 'newemail@example.com'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify OTP was created
        otp_record = EmailOTP.objects.filter(
            user=self.user,
            new_email='newemail@example.com'
        ).first()
        self.assertIsNotNone(otp_record)

        # Confirm email with OTP
        confirm_otp_url = reverse('user:verify-email-otp')
        response = self.client.post(confirm_otp_url, {
            'new_email': 'newemail@example.com',
            'otp': otp_record.otp
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify email was updated
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, 'newemail@example.com')

    # JWT SECURITY TESTS
    def test_jwt_security(self):
        """Test JWT token security"""
        # Test login gets tokens
        response = self.client.post(self.login_url, {
            'email': 'test@example.com',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        access_token = response.data['access']
        refresh_token = response.data['refresh']

        # Test token works
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        me_url = reverse('user:me')
        response = self.client.get(me_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Test token refresh
        refresh_url = reverse('user:token_refresh')
        self.client.credentials()
        response = self.client.post(refresh_url, {'refresh': refresh_token})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        new_access_token = response.data['access']
        self.assertNotEqual(access_token, new_access_token)

        # Test logout blacklists token
        logout_url = reverse('user:logout')
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {new_access_token}')
        response = self.client.post(logout_url, {'refresh': response.data['refresh']})
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)

    # PERMISSION TESTS
    def test_role_based_permissions(self):
        """Test role-based access control"""
        regular_user = User.objects.create_user(
            email='regular@example.com',
            password='testpass123',
            fname='Regular',
            lname='User',
            phone='1234567892'
        )
        
        # Regular user cannot unblock accounts
        refresh = RefreshToken.for_user(regular_user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        
        response = self.client.post(self.unblock_url, {
            'email': 'test@example.com'
        })
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

        # Admin can unblock accounts
        refresh = RefreshToken.for_user(self.admin)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        
        response = self.client.post(self.unblock_url, {
            'email': 'test@example.com'
        })
        self.assertIn(response.status_code, [status.HTTP_200_OK, status.HTTP_404_NOT_FOUND])

    # SECURITY VULNERABILITY TESTS
    def test_security_vulnerabilities(self):
        """Test protection against common vulnerabilities"""
        # Test SQL injection protection
        sql_payloads = ["'; DROP TABLE users; --", "' OR '1'='1"]
        for payload in sql_payloads:
            response = self.client.post(self.login_url, {
                'email': payload,
                'password': 'testpass123'
            })
            self.assertIn(response.status_code, [
                status.HTTP_401_UNAUTHORIZED,
                status.HTTP_400_BAD_REQUEST
            ])

        # Test invalid token rejection
        self.client.credentials(HTTP_AUTHORIZATION='Bearer invalid_token')
        me_url = reverse('user:me')
        response = self.client.get(me_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # Test mass assignment protection
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        
        response = self.client.patch(me_url, {
            'fname': 'Updated',
            'role': 'admin',  # Should not be updatable
            'is_staff': True,  # Should not be updatable
        })
        
        self.user.refresh_from_db()
        self.assertEqual(self.user.fname, 'Updated')
        self.assertNotEqual(self.user.role, 'admin')
        self.assertFalse(self.user.is_staff)

    # CONFIGURATION TESTS
    def test_security_configuration(self):
        """Test security configuration settings"""
        from django.conf import settings
        
        # Test JWT configuration
        jwt_settings = settings.SIMPLE_JWT
        self.assertEqual(jwt_settings['ACCESS_TOKEN_LIFETIME'].total_seconds(), 300)  # 5 minutes
        self.assertTrue(jwt_settings['ROTATE_REFRESH_TOKENS'])
        self.assertTrue(jwt_settings['BLACKLIST_AFTER_ROTATION'])

        # Test password validators
        validators = settings.AUTH_PASSWORD_VALIDATORS
        validator_names = [v['NAME'] for v in validators]
        expected_validators = [
            'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
            'django.contrib.auth.password_validation.MinimumLengthValidator',
            'django.contrib.auth.password_validation.CommonPasswordValidator',
            'django.contrib.auth.password_validation.NumericPasswordValidator',
        ]
        for validator in expected_validators:
            self.assertIn(validator, validator_names)

    # EDGE CASES
    def test_edge_cases(self):
        """Test edge cases and error handling"""
        # Test empty login request
        response = self.client.post(self.login_url, {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # Test nonexistent user
        response = self.client.post(self.login_url, {
            'email': 'nonexistent@example.com',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # Test user isolation (lockout affects only specific user)
        user2 = User.objects.create_user(
            email='user2@example.com',
            password='testpass123',
            fname='User',
            lname='Two',
            phone='1234567894'
        )

        # Lock first user
        for i in range(5):
            self.client.post(self.login_url, {
                'email': 'test@example.com',
                'password': 'wrongpassword'
            })

        # Second user should still work
        response = self.client.post(self.login_url, {
            'email': 'user2@example.com',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Verify isolation
        self.user.refresh_from_db()
        user2.refresh_from_db()
        self.assertTrue(self.user.is_blocked)
        self.assertFalse(user2.is_blocked)