'''
Test model user
'''

from core import models
from django.test import TestCase
from django.contrib.auth import get_user_model
import random
import datetime
import time
from django.utils import timezone

class ModelTests(TestCase):
    def test_create_user_successful(self):

        email = 'test@example.com'
        password = 'testpass123'

        user = get_user_model().objects.create_user(
            email=email,
            password=password
        )

        self.assertEqual(user.email, email)
        self.assertTrue(user.check_password(password))

    def test_new_user_email_normalized(self):
        """Test email is normalized for new users."""
        sample_emails = [
            ['test1@EXAMPLE.com', 'test1@example.com'],
            ['Test2@Example.com', 'Test2@example.com'],
            ['TEST3@EXAMPLE.COM', 'TEST3@example.com'],
            ['test4@example.COM', 'test4@example.com'],
        ]
        for email, expected in sample_emails:
            user = get_user_model().objects.create_user(email, 'sample123')
            self.assertEqual(user.email, expected)

    def test_new_user_without_email_raises_error(self):
        """Test that creating a user without an email raises a ValueError."""
        with self.assertRaises(ValueError):
            get_user_model().objects.create_user('', 'test123')

    def test_super_user(self):
        """Test creating a superuser."""
        user = get_user_model().objects.create_superuser(
            'test@example.com',
            'test123'
        )

        self.assertTrue(user.is_superuser)
        self.assertTrue(user.is_staff)

    def test_create_email_otp(self):
        '''Check Creation of Email OTP'''
        email = 'test@example.com'
        password = 'testpass123'

        user = get_user_model().objects.create_user(
            email=email,
            password=password
        )

        otp = random.randrange(100000,999999)

        res = models.EmailOTP.objects.create(
            user = user,
            new_email = 'newmail@example.com',
            otp = otp,
        )

        self.assertEqual(res.user, user)
        self.assertEqual(res.new_email, 'newmail@example.com')
        self.assertEqual(res.otp, otp)
        self.assertFalse(res.is_otp_expired())


        res.created_at = timezone.now() - datetime.timedelta(minutes=11)
        res.save()

        self.assertTrue(res.is_otp_expired())

        self.assertIsNotNone(res.created_at)
        self.assertTrue(timezone.is_aware(res.created_at))
