from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone

User = get_user_model()


@override_settings(
    REST_FRAMEWORK={
        'DEFAULT_THROTTLE_CLASSES': [],
        'DEFAULT_THROTTLE_RATES': {},
    }
)
class AccountLockoutTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            fname='Test',
            lname='User',
            phone='1234567890'
        )
        self.login_url = reverse('user:token')

    def test_successful_login_resets_failed_attempts(self):
        """Test that successful login resets failed_login_attempts to 0"""
        # Set some failed attempts
        self.user.failed_login_attempts = 3
        self.user.save()

        response = self.client.post(self.login_url, {
            'email': 'test@example.com',
            'password': 'testpass123'
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 0)

    def test_failed_login_increments_attempts(self):
        """Test that failed login increments failed_login_attempts"""
        response = self.client.post(self.login_url, {
            'email': 'test@example.com',
            'password': 'wrongpassword'
        })

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 1)
        self.assertIsNotNone(self.user.last_failed_login)

    def test_account_blocked_after_5_failed_attempts(self):
        """Test that account gets blocked after 5 failed login attempts"""
        # Make 5 failed login attempts
        for i in range(5):
            response = self.client.post(self.login_url, {
                'email': 'test@example.com',
                'password': 'wrongpassword'
            })
            self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 5)
        self.assertTrue(self.user.is_blocked)

    def test_blocked_account_cannot_login(self):
        """Test that blocked account cannot login even with correct password"""
        # Block the account
        self.user.is_blocked = True
        self.user.save()

        response = self.client.post(self.login_url, {
            'email': 'test@example.com',
            'password': 'testpass123'
        })

        self.assertEqual(response.status_code, status.HTTP_423_LOCKED)
        self.assertIn('Account blocked', response.data['error'])

    def test_inactive_account_cannot_login(self):
        """Test that inactive account cannot login"""
        self.user.is_active = False
        self.user.save()

        response = self.client.post(self.login_url, {
            'email': 'test@example.com',
            'password': 'testpass123'
        })

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('Wrong username or password', response.data['error'])

    def test_lockout_check_function_with_active_user(self):
        """Test lockout check function with active, unblocked user"""
        from user.views import check_account_lockout
        
        result = check_account_lockout(self.user)
        self.assertIsNone(result)

    def test_lockout_check_function_with_blocked_user(self):
        """Test lockout check function with blocked user"""
        from user.views import check_account_lockout
        
        self.user.is_blocked = True
        self.user.save()
        
        result = check_account_lockout(self.user)
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, status.HTTP_423_LOCKED)


@override_settings(
    REST_FRAMEWORK={
        'DEFAULT_THROTTLE_CLASSES': [],
        'DEFAULT_THROTTLE_RATES': {},
    }
)
class UnblockUserViewTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.admin_user = User.objects.create_user(
            email='admin@example.com',
            password='adminpass123',
            fname='Admin',
            lname='User',
            phone='1234567891',
            role='admin'
        )
        self.blocked_user = User.objects.create_user(
            email='blocked@example.com',
            password='blockedpass123',
            fname='Blocked',
            lname='User',
            phone='1234567892',
            is_blocked=True,
            failed_login_attempts=5
        )
        self.unblock_url = reverse('user:unblock_user')

    def authenticate_admin(self):
        refresh = RefreshToken.for_user(self.admin_user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

    def test_admin_can_unblock_user(self):
        """Test that admin can unblock a blocked user"""
        self.authenticate_admin()

        response = self.client.post(self.unblock_url, {
            'email': 'blocked@example.com'
        })

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['success'], 'Account unblocked successfully')
        
        self.blocked_user.refresh_from_db()
        self.assertFalse(self.blocked_user.is_blocked)
        self.assertEqual(self.blocked_user.failed_login_attempts, 0)

    def test_unblock_nonexistent_user(self):
        """Test unblocking nonexistent user"""
        self.authenticate_admin()

        response = self.client.post(self.unblock_url, {
            'email': 'nonexistent@example.com'
        })

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data['error'], 'User not found')

    def test_unblock_without_email(self):
        """Test unblock request without email"""
        self.authenticate_admin()

        response = self.client.post(self.unblock_url, {})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['error'], 'Email Required')

    def test_unblock_without_authentication(self):
        """Test unblock request without authentication"""
        response = self.client.post(self.unblock_url, {
            'email': 'blocked@example.com'
        })

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_regular_user_cannot_unblock(self):
        """Test that regular user cannot unblock accounts"""
        regular_user = User.objects.create_user(
            email='regular@example.com',
            password='regularpass123',
            fname='Regular',
            lname='User',
            phone='1234567893'
        )
        
        refresh = RefreshToken.for_user(regular_user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        response = self.client.post(self.unblock_url, {
            'email': 'blocked@example.com'
        })

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


@override_settings(
    REST_FRAMEWORK={
        'DEFAULT_THROTTLE_CLASSES': [],
        'DEFAULT_THROTTLE_RATES': {},
    }
)
class AccountLockoutIntegrationTestCase(TestCase):
    """Integration tests for complete account lockout flow"""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email='integration@example.com',
            password='testpass123',
            fname='Integration',
            lname='Test',
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

    def test_complete_lockout_and_recovery_flow(self):
        """Test complete flow: lockout -> admin unblock -> successful login"""
        # Step 1: Lock account with failed attempts
        for i in range(5):
            response = self.client.post(self.login_url, {
                'email': 'integration@example.com',
                'password': 'wrongpassword'
            })

        self.user.refresh_from_db()
        self.assertTrue(self.user.is_blocked)
        self.assertEqual(self.user.failed_login_attempts, 5)

        # Step 2: Verify account is locked
        response = self.client.post(self.login_url, {
            'email': 'integration@example.com',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, status.HTTP_423_LOCKED)

        # Step 3: Admin unblocks account
        refresh = RefreshToken.for_user(self.admin)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')
        
        response = self.client.post(self.unblock_url, {
            'email': 'integration@example.com'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Step 4: User can now login successfully
        self.client.credentials()  # Clear admin credentials
        response = self.client.post(self.login_url, {
            'email': 'integration@example.com',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)

    def test_lockout_with_mixed_users(self):
        """Test that lockout is isolated between different users"""
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
                'email': 'integration@example.com',
                'password': 'wrongpassword'
            })

        # Second user should still be able to login
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