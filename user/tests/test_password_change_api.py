from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from django.utils import timezone
from core.models import PasswordHistory
import datetime

PASS_CHANGE_WITH_PASS_URL = reverse('user:passchange')
JWT_TOKEN_URL = reverse('user:token')

class PublicTestCase(TestCase):
    '''Public Tests for Password Change API'''
    
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email="test@example.com",
            password='testpass123',
            fname='Test',
            lname='Case',
            phone='7896541230'
        )
        self.client = APIClient()

    def test_unauthorized_access(self):
        '''Test unauthorized access is prohibited'''
        payload = {
            'old_password': 'testpass123',
            'new_password': 'newpass123',
        }
        res = self.client.post(PASS_CHANGE_WITH_PASS_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_invalid_token(self):
        '''Test invalid token access'''
        self.client.credentials(HTTP_AUTHORIZATION="Bearer invalid_token")
        payload = {
            'old_password': 'testpass123',
            'new_password': 'newpass123',
        }
        res = self.client.post(PASS_CHANGE_WITH_PASS_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)


class PrivateTestCase(TestCase):
    '''Authenticated User Test Cases'''
    
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email="new@example.com",
            password='newpass123',
            fname='Hello',
            lname='World',
            phone='1478523690'
        )
        self.client = APIClient()
        tokens = self.client.post(JWT_TOKEN_URL, {
            'email': 'new@example.com',
            'password': 'newpass123'
        }, format='json').data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")

    def test_successful_password_change(self):
        '''Test successful password change'''
        payload = {
            'old_password': 'newpass123',
            'new_password': 'newpassword123'
        }
        res = self.client.post(PASS_CHANGE_WITH_PASS_URL, payload)
        
        self.user.refresh_from_db()
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data, {'success': 'Successfully Password Changed.'})
        self.assertTrue(self.user.check_password(payload['new_password']))
        self.assertFalse(self.user.check_password('newpass123'))

    def test_incorrect_old_password(self):
        '''Test incorrect old password'''
        payload = {
            'old_password': "wrongpass123",
            'new_password': "testpass@456"
        }
        res = self.client.post(PASS_CHANGE_WITH_PASS_URL, payload)
        
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(res.data, {'error': 'Incorrect Password.'})
        self.assertTrue(self.user.check_password('newpass123'))  # Password unchanged


class ValidationTestCase(TestCase):
    '''Input Validation Test Cases'''
    
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email="validation@example.com",
            password='validpass123',
            fname='Valid',
            lname='User',
            phone='9876543210'
        )
        self.client = APIClient()
        tokens = self.client.post(JWT_TOKEN_URL, {
            'email': 'validation@example.com',
            'password': 'validpass123'
        }, format='json').data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")

    def test_missing_old_password(self):
        '''Test missing old password field'''
        payload = {'new_password': 'newpass123'}
        res = self.client.post(PASS_CHANGE_WITH_PASS_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(res.data, {'error': 'Invalid Request'})

    def test_missing_new_password(self):
        '''Test missing new password field'''
        payload = {'old_password': 'validpass123'}
        res = self.client.post(PASS_CHANGE_WITH_PASS_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(res.data, {'error': 'Invalid Request'})

    def test_empty_old_password(self):
        '''Test empty old password'''
        payload = {
            'old_password': '',
            'new_password': 'newpass123'
        }
        res = self.client.post(PASS_CHANGE_WITH_PASS_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(res.data, {'error': 'Invalid Request'})

    def test_empty_new_password(self):
        '''Test empty new password'''
        payload = {
            'old_password': 'validpass123',
            'new_password': ''
        }
        res = self.client.post(PASS_CHANGE_WITH_PASS_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(res.data, {'error': 'Invalid Request'})

    def test_short_new_password(self):
        '''Test new password too short (less than 5 chars)'''
        payload = {
            'old_password': 'validpass123',
            'new_password': '1234'
        }
        res = self.client.post(PASS_CHANGE_WITH_PASS_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(res.data, {'error': 'Invalid Request'})

    def test_same_old_new_password(self):
        '''Test same old and new password'''
        payload = {
            'old_password': 'validpass123',
            'new_password': 'validpass123'
        }
        res = self.client.post(PASS_CHANGE_WITH_PASS_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(res.data, {'error': 'Please use password other than recent ones'})


class PasswordHistoryTestCase(TestCase):
    '''Password History and Reuse Test Cases'''
    
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email="history@example.com",
            password='initialpass123',
            fname='History',
            lname='User',
            phone='5555555555'
        )
        self.client = APIClient()
        tokens = self.client.post(JWT_TOKEN_URL, {
            'email': 'history@example.com',
            'password': 'initialpass123'
        }, format='json').data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")

    def test_password_reuse_prevention(self):
        '''Test prevention of recent password reuse'''
        # Change password first time
        payload1 = {
            'old_password': 'initialpass123',
            'new_password': 'secondpass123'
        }
        res1 = self.client.post(PASS_CHANGE_WITH_PASS_URL, payload1)
        self.assertEqual(res1.status_code, status.HTTP_200_OK)
        
        # Try to reuse initial password
        payload2 = {
            'old_password': 'secondpass123',
            'new_password': 'initialpass123'
        }
        res2 = self.client.post(PASS_CHANGE_WITH_PASS_URL, payload2)
        self.assertEqual(res2.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(res2.data, {'error': 'Please use password other than recent ones'})

    def test_password_history_creation(self):
        '''Test password history is created on change'''
        initial_count = PasswordHistory.objects.filter(user=self.user).count()
        
        payload = {
            'old_password': 'initialpass123',
            'new_password': 'newhistorypass123'
        }
        res = self.client.post(PASS_CHANGE_WITH_PASS_URL, payload)
        
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        final_count = PasswordHistory.objects.filter(user=self.user).count()
        self.assertEqual(final_count, initial_count + 1)


class EdgeCaseTestCase(TestCase):
    '''Edge Cases and Special Scenarios'''
    
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email="edge@example.com",
            password='edgepass123',
            fname='Edge',
            lname='Case',
            phone='1111111111'
        )
        self.client = APIClient()
        tokens = self.client.post(JWT_TOKEN_URL, {
            'email': 'edge@example.com',
            'password': 'edgepass123'
        }, format='json').data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")

    def test_special_characters_password(self):
        '''Test password with special characters'''
        payload = {
            'old_password': 'edgepass123',
            'new_password': 'P@ssw0rd!@#$%'
        }
        res = self.client.post(PASS_CHANGE_WITH_PASS_URL, payload)
        
        self.user.refresh_from_db()
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertTrue(self.user.check_password('P@ssw0rd!@#$%'))

    def test_unicode_password(self):
        '''Test password with unicode characters'''
        payload = {
            'old_password': 'edgepass123',
            'new_password': 'pässwörd123'
        }
        res = self.client.post(PASS_CHANGE_WITH_PASS_URL, payload)
        
        self.user.refresh_from_db()
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertTrue(self.user.check_password('pässwörd123'))

    def test_very_long_password(self):
        '''Test very long password'''
        long_password = 'a' * 200
        payload = {
            'old_password': 'edgepass123',
            'new_password': long_password
        }
        res = self.client.post(PASS_CHANGE_WITH_PASS_URL, payload)
        
        self.user.refresh_from_db()
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertTrue(self.user.check_password(long_password))

    def test_whitespace_password(self):
        '''Test password with whitespace'''
        payload = {
            'old_password': 'edgepass123',
            'new_password': 'pass word 123'
        }
        res = self.client.post(PASS_CHANGE_WITH_PASS_URL, payload)
        
        self.user.refresh_from_db()
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertTrue(self.user.check_password('pass word 123'))

    def test_numeric_only_password(self):
        '''Test numeric only password'''
        payload = {
            'old_password': 'edgepass123',
            'new_password': '123456789'
        }
        res = self.client.post(PASS_CHANGE_WITH_PASS_URL, payload)
        
        self.user.refresh_from_db()
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertTrue(self.user.check_password('123456789'))


class HTTPMethodTestCase(TestCase):
    '''HTTP Method Test Cases'''
    
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email="method@example.com",
            password='methodpass123',
            fname='Method',
            lname='Test',
            phone='2222222222'
        )
        self.client = APIClient()
        tokens = self.client.post(JWT_TOKEN_URL, {
            'email': 'method@example.com',
            'password': 'methodpass123'
        }, format='json').data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")

    def test_get_method_not_allowed(self):
        '''Test GET method not allowed'''
        res = self.client.get(PASS_CHANGE_WITH_PASS_URL)
        self.assertEqual(res.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_put_method_not_allowed(self):
        '''Test PUT method not allowed'''
        payload = {
            'old_password': 'methodpass123',
            'new_password': 'newmethod123'
        }
        res = self.client.put(PASS_CHANGE_WITH_PASS_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_delete_method_not_allowed(self):
        '''Test DELETE method not allowed'''
        res = self.client.delete(PASS_CHANGE_WITH_PASS_URL)
        self.assertEqual(res.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_patch_method_not_allowed(self):
        '''Test PATCH method not allowed'''
        payload = {
            'old_password': 'methodpass123',
            'new_password': 'newmethod123'
        }
        res = self.client.patch(PASS_CHANGE_WITH_PASS_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)