'''
Test User API
'''

from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from core.models import EmailOTP

CREATE_USER_URL = reverse('user:create')
JWT_TOKEN_URL = reverse('user:token')
JWT_REFRESH_TOKEN_URL = reverse('user:token_refresh')
LOGOUT_URL = reverse('user:logout')
UPDATE_USER_URL = reverse("user:me")
REQ_EMAIL_CHANGE = reverse('user:request-email-otp')
VERIFY_EMAIL_CHANGE = reverse('user:verify-email-otp')


def create_user(**params):
    '''Create and return a new user instance'''
    return get_user_model().objects.create_user(**params)


class PublicUserAPITest(TestCase):
    '''Public Tests for User API'''

    def setUp(self):
        self.client = APIClient()

    def test_user_create(self):
        '''Test creating a user is successful'''
        payload = {
            'email': 'test@example.com',
            'fname': 'Fname',
            'lname': 'Lname',
            'phone': '1234567890',
            'password': 'testpass123',
            'password2': 'testpass123',
        }

        res = self.client.post(CREATE_USER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        self.assertEqual(res.data['email'], payload['email'])
        self.assertEqual(res.data['fname'], payload['fname'])
        self.assertEqual(res.data['lname'], payload['lname'])
        self.assertEqual(res.data['phone'], payload['phone'])
        self.assertNotIn('password', res.data)
        self.assertNotIn('password2', res.data)
        user = get_user_model().objects.get(email=payload['email'])
        self.assertTrue(user.check_password(payload['password']))

    def test_user_exists(self):
        '''Test if the user exists'''

        payload = {
            'email': 'test@example.com',
            'fname': 'Fname',
            'lname': 'Lname',
            'phone': '1234567890',
            'password': 'testpass123',

        }

        create_user(**payload)
        payload['password2'] = 'testpass123'
        res = self.client.post(CREATE_USER_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_phone_exist(self):
        '''Test if the phone number exists'''

        payload = {
            'email': 'test@example.com',
            'fname': 'Fname',
            'lname': 'Lname',
            'phone': '1234567890',
            'password': 'testpass123',

        }

        create_user(**payload)
        payload['email'] = 'test2@example.com'
        payload['password2'] = 'testpass123'
        res = self.client.post(CREATE_USER_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_min_phone_length(self):
        '''Test phone number length'''

        payload = {
            'email': 'test@example.com',
            'fname': 'Fname',
            'lname': 'Lname',
            'phone': '1234',
            'password': 'testpass123',
            'password2': 'testpass123',
        }

        res = self.client.post(CREATE_USER_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_max_phone_length(self):
        '''Test phone number length'''

        payload = {
            'email': 'test@example.com',
            'fname': 'Fname',
            'lname': 'Lname',
            'phone': '12345678901234567890',
            'password': 'testpass123',
            'password2': 'testpass123',
        }

        res = self.client.post(CREATE_USER_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_too_short(self):
        '''Test for short password'''

        payload = {
            'email': 'test@example.com',
            'fname': 'Fname',
            'lname': 'Lname',
            'phone': '1234567890',
            'password': 'test',
            'password2': 'test',
        }

        res = self.client.post(CREATE_USER_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        user_exists = get_user_model().objects.filter(
            email=payload['email']).exists()
        self.assertFalse(user_exists)

    def test_password_not_matched(self):
        '''Test for mismatched password'''

        payload = {
            'email': 'test@example.com',
            'fname': 'Fname',
            'lname': 'Lname',
            'phone': '1234567890',
            'password': 'testpass123',
            'password2': 'testpass456',
        }

        res = self.client.post(CREATE_USER_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        user_exists = get_user_model().objects.filter(
            email=payload['email']).exists()
        self.assertFalse(user_exists)

    def test_jwt_token_auth_api(self):
        '''Test JWT Auth Token API'''

        user_details = {
            'email': 'test@example.com',
            'fname': 'Fname',
            'lname': 'Lname',
            'phone': '1234567890',
            'password': 'testpass123',

        }

        create_user(**user_details)
        payload = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        tokens = self.client.post(JWT_TOKEN_URL, payload, format='json').data
        self.assertIn('access', tokens)
        self.assertIn('refresh', tokens)
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        res = self.client.post(JWT_REFRESH_TOKEN_URL, {
                               'refresh': tokens['refresh']})
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn("refresh", res.data)
        self.assertIn('access', res.data)

    def test_unauthorized_entry(self):
        '''Test for unauthorized entry'''

        res = self.client.get(UPDATE_USER_URL)

        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_blank_password(self):
        '''Test for Blank password for login'''

        user_details = {
            'email': 'test@example.com',
            'fname': 'Fname',
            'lname': 'Lname',
            'phone': '1234567890',
            'password': 'testpass123',

        }

        create_user(**user_details)
        payload = {'email': 'test@example.com', 'password': ''}
        res = self.client.post(JWT_TOKEN_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertNotIn('access', res.data)
        self.assertNotIn('refresh', res.data)

    def test_bad_cred(self):
        '''Test for bad credentials for login'''

        user_details = {
            'email': 'test@example.com',
            'fname': 'Fname',
            'lname': 'Lname',
            'phone': '1234567890',
            'password': 'testpass123',

        }

        create_user(**user_details)
        payload = {'email': 'wrong@example.com', 'password': 'wrongpass'}
        res = self.client.post(JWT_TOKEN_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertNotIn('access', res.data)
        self.assertNotIn('refresh', res.data)


class PrivateTestCase(TestCase):
    '''Authorized Test Cases'''

    def setUp(self):
        '''Setup Function for Authorized Test Cases'''
        self.user = create_user(
            email='test@example.com',
            fname='Fname',
            lname='Lname',
            phone='1234567890',
            password='testpass123',
        )
        self.client = APIClient()

    def login_function(self):
        '''Function for login the created user'''

        payload = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        tokens = self.client.post(JWT_TOKEN_URL, payload, format='json').data

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")

        return tokens

    def test_logout(self):
        '''Testing the logout function'''
        tokens = self.login_function()

        refresh_token = {'refresh': tokens['refresh']}

        res = self.client.post(LOGOUT_URL, refresh_token)

        self.assertEqual(res.status_code, status.HTTP_205_RESET_CONTENT)

        check_res = self.client.post(JWT_REFRESH_TOKEN_URL, refresh_token)

        self.assertIn(check_res.status_code, [
                      status.HTTP_401_UNAUTHORIZED, status.HTTP_400_BAD_REQUEST])

    def update_user_with_valid_fields(self):
        '''Test for updating user with valid fields'''
        payload = {
            'fname': 'New Fname',
            'lname': "New Lname",
            'phone': '1234560987'
        }

        self.login_function()
        res = self.client.patch(UPDATE_USER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['fname'], payload['fname'])
        self.assertEqual(res.data['lname'], payload['lname'])
        self.assertEqual(res.data['phone'], payload['phone'])
        self.assertEqual(res.data['email'], self.user.email)
        self.assertNotIn('password', res.data)

    def test_email_change_rejection(self):
        '''Test for email change req rejection'''
        payload = {'email': 'newmail@example.com'}

        self.login_function()
        res = self.client.patch(UPDATE_USER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', res.data)
        # print(res.data['email'])

    def test_password_change_rejection(self):
        '''Test for password change req rejection'''
        payload = {'password': 'newpass123'}

        self.login_function()
        res = self.client.patch(UPDATE_USER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', res.data)
        # print(res.data['password'])
