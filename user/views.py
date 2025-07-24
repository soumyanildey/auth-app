from rest_framework import generics, permissions, status
from .serializers import (
    UserSerializer, CustomTokenObtainPairSerializer, LogoutSerializer,
    EmailOTPConfirmSerializer, EmailOTPRequestSerializer,
    PasswordChangeWithOldPasswordSerializer
)
from rest_framework.settings import api_settings
from . import permissions as custom_permissions
from django.contrib.auth import get_user_model, logout
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework.views import APIView
from core.models import EmailOTP, PasswordHistory
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
import datetime
from django.db import transaction
import secrets
from .utils import generate_and_send_otp, validate_otp
from django.contrib.auth.hashers import check_password


def check_password_reuse(user, raw_password):
    '''Check for last 10 passwords if reused'''
    old_passwords = PasswordHistory.objects.filter(
        user=user).order_by('-changed_at')[:10]
    for old in old_passwords:
        if check_password(raw_password, old.password):
            return True
    return False


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
    serializer_class = EmailOTPRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            new_email = serializer.validated_data['new_email']

            if new_email.lower() == request.user.email.lower():
                if request.user.is_email_verified:
                    return Response({'message': 'Email is already verified'}, status=400)

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
    serializer_class = EmailOTPConfirmSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
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


class PasswordChangeWithOldPasswordView(APIView):
    '''View for password change with old password'''
    serializer_class = PasswordChangeWithOldPasswordSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            old_pass = serializer.validated_data['old_password']
            new_pass = serializer.validated_data['new_password']

            try:
                if not request.user.check_password(old_pass):
                    return Response({'error': 'Incorrect Password.'}, status=400)
                if check_password_reuse(request.user, new_pass):
                    return Response({'error': 'Please use password other than recent ones'}, status=400)
                request.user.set_password(new_pass)
                request.user.save()
                return Response({'success': 'Successfully Password Changed.'}, status=200)

            except Exception:
                return Response({'error': 'Something Went Wrong. Please try again later.'}, status=400)

        return Response({'error': 'Invalid Request'}, status=400)


class PublicThrottleTest(APIView):

    def get(self,request):
        return Response({'Success':f'Success for {request.user}'},status=200)


class PrivateThrottleTest(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self,request):
        return Response({'Success':f'Success for {request.user}'},status=200)