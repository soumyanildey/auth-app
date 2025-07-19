from rest_framework import generics, permissions, status
from .serializers import (
    UserSerializer, CustomTokenObtainPairSerializer, LogoutSerializer,
    EmailOTPConfirmSerializer, EmailOTPRequestSerializer,
)
from rest_framework.settings import api_settings
from . import permissions as custom_permissions
from django.contrib.auth import get_user_model, logout
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework.views import APIView
from core.models import EmailOTP
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
import datetime
from django.db import transaction
import secrets
from .utils import generate_and_send_otp, validate_otp


class CreateUserView(generics.CreateAPIView):
    '''Viewset for handling the create user serializer'''
    serializer_class = UserSerializer

    def perform_create(self, serializer):
        # User active by default, email needs verification
        user = serializer.save(is_email_verified=False)
        generate_and_send_otp(
            user, user.email, subject="Verify Your Email", purpose="registration")


class UpdateUserView(generics.RetrieveUpdateAPIView):
    '''Viewset for handling the update user serializer'''
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        '''Update current user instance'''
        return self.request.user


class AdminUserView(generics.RetrieveUpdateDestroyAPIView):
    '''Viewset for handling the admin role'''
    serializer_class = UserSerializer
    permission_classes = [
        permissions.IsAuthenticated, custom_permissions.IsAdmin]
    queryset = get_user_model().objects.exclude(
        role__in=['superadmin', 'admin'])


class SuperAdminUserView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated,
                          custom_permissions.IsSuperAdmin]
    queryset = get_user_model().objects.all()
    lookup_field = 'pk'


class CustomTokenObtainPairView(TokenObtainPairView):
    '''Custom token view'''
    serializer_class = CustomTokenObtainPairSerializer


class LogoutView(APIView):
    '''Implements Logout Functionality'''
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = LogoutSerializer

    def post(self, request):
        try:
            logout(request)
            refresh_token = request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class RequestEmailOTPView(APIView):
    '''APIView for requesting email change with OTP'''
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = EmailOTPRequestSerializer(data=request.data)
        if serializer.is_valid():
            new_email = serializer.validated_data['new_email']

            if new_email.lower() == request.user.email.lower():
                return Response({'message': 'Both emails are the same'}, status=400)

            # Check if email is already in use by another user
            if get_user_model().objects.filter(email=new_email).exclude(id=request.user.id).exists():
                return Response({'error': 'Email already in use by another account'}, status=400)

            with transaction.atomic():
                one_hour_ago = timezone.now() - datetime.timedelta(hours=1)
                recent_count = EmailOTP.objects.select_for_update().filter(
                    user=request.user,
                    new_email=new_email,
                    created_at__gte=one_hour_ago
                ).count()

                if recent_count >= 3:
                    return Response({'error': 'Too many requests. Try again later.'}, status=429)

                generate_and_send_otp(
                    request.user, new_email, subject="Change Email OTP", purpose="change_email")

            return Response({'message': 'OTP sent to new E-Mail'}, status=200)
        return Response(serializer.errors, status=400)


class ConfirmEmailOTPView(APIView):
    '''APIView for Confirmation of Email OTP'''
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = EmailOTPConfirmSerializer(data=request.data)
        if serializer.is_valid():
            new_email = serializer.validated_data['new_email']
            otp = serializer.validated_data['otp']

            is_valid, result = validate_otp(request.user, new_email, otp)
            if not is_valid:
                return Response({'error': result}, status=429 if "Too many failed attempts" in result else 400)

            # OTP is valid
            request.user.email = new_email
            request.user.is_email_verified = True
            request.user.save()
            result.delete()  # Delete OTP record

            return Response({'success': 'Email verified and updated'}, status=200)

        return Response({'error': 'Invalid Request'}, status=400)
