from rest_framework.test import APITestCase, APIClient
from django.contrib.auth import get_user_model
from django.core.cache import cache
from time import sleep
from rest_framework import status
from django.urls import reverse


class ThrottleTest(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.Publicurl = reverse("user:public_throttle_test")
        self.Privateurl = reverse("user:private_throttle_test")
        self.user = get_user_model().objects.create_user(
            email='test@example.com', password='testpass')
        cache.clear()
        self.JWT_URL = reverse('user:token')

    def tearDown(self):
        cache.clear()

    def test_unauth_view(self):
        '''Throttle test for unauthorized users'''
        for _ in range(1, 101):
            response = self.client.get(self.Publicurl)
            self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client.get(self.Publicurl)
        self.assertEqual(response.status_code,
                         status.HTTP_429_TOO_MANY_REQUESTS)

    def test_auth_view(self):
        '''Throttle test for authorized users'''
        payload = {
            'email':'test@example.com',
            'password':'testpass'
        }
        res = self.client.post(self.JWT_URL, payload,format='json').data
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {res['access']}")
        for _ in range(1, 1001):
            response = self.client.get(self.Privateurl)
            self.assertEqual(response.status_code, status.HTTP_200_OK)

        response = self.client.get(self.Privateurl)
        self.assertEqual(response.status_code,
                         status.HTTP_429_TOO_MANY_REQUESTS)
