from rest_framework import generics, permissions, status
from rest_framework.exceptions import PermissionDenied
from .serializers import (
    UserSerializer, CustomTokenObtainPairSerializer, LogoutSerializer,
    EmailOTPConfirmSerializer, EmailOTPRequestSerializer,
    PasswordChangeWithOldPasswordSerializer, Verify2FASerializer,
    PasswordResetSerializer, PasswordResetConfirmSerializer, UnblockUserSerializer,
    PhoneOTPVerifySerializer,
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
from .utils import generate_and_send_otp, validate_otp, generate_and_send_sms_otp, log_activity
from django.contrib.auth.hashers import check_password
import base64
import io
import pyotp
import qrcode
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from allauth.socialaccount.models import SocialAccount
import requests
from django.shortcuts import redirect


def check_account_lockout(user):
    if not user.is_active:
        return Response({'error': 'Wrong username or password.'}, status=status.HTTP_400_BAD_REQUEST)
    if user.is_blocked:
        return Response({'error': 'Account blocked due to too many failed login attempts. Please contact support.'}, status=status.HTTP_423_LOCKED)
    return None


def check_password_reuse(user, raw_password):
    """
    Check if the given raw_password matches any of the user's last 10 passwords.
    """
    # Evaluate the queryset to avoid slicing errors
    recent_passwords = list(
        PasswordHistory.objects.filter(user=user)
        .order_by('-changed_at')[:10]
    )

    for old in recent_passwords:
        if check_password(raw_password, old.password):
            return True
    return False


class CreateUserView(generics.CreateAPIView):
    '''Viewset for handling the create user serializer'''
    serializer_class = UserSerializer

    def perform_create(self, serializer):
        # User active by default, email needs verification
        user = serializer.save(is_email_verified=False)
        log_activity(user, 'profile_update', self.request)
        generate_and_send_otp(
            user, user.email, subject="Verify Your Email", purpose="registration")


class UpdateUserView(generics.RetrieveUpdateAPIView):
    '''Viewset for handling the update user profile'''
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        '''Update current user instance'''
        return self.request.user

    def perform_update(self, serializer):
        serializer.save()
        log_activity(self.request.user, 'profile_update', self.request)


class DeleteUserView(generics.DestroyAPIView):
    '''Viewset for handling Delete User profile'''
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        '''Delete Current User'''
        return self.request.user


class AdminUserView(generics.RetrieveUpdateDestroyAPIView):
    '''Viewset for handling the admin role'''
    serializer_class = UserSerializer
    permission_classes = [
        permissions.IsAuthenticated, custom_permissions.IsAdmin]
    queryset = get_user_model().objects.filter(role='user')
    
    def get(self, request, pk=None, *args, **kwargs):
        if pk:
            return super().get(request, *args, **kwargs)
        # List users only
        users = self.get_queryset()
        serializer = self.serializer_class(users, many=True)
        return Response(serializer.data)
    
    def put(self, request, pk=None, *args, **kwargs):
        return Response({'error': 'Update not allowed'}, status=405)
    
    def patch(self, request, pk=None, *args, **kwargs):
        return Response({'error': 'Update not allowed'}, status=405)


class SuperAdminUserView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated,
                          custom_permissions.IsSuperAdmin]
    queryset = get_user_model().objects.filter(role='user')
    lookup_field = 'pk'
    
    def get(self, request, pk=None, *args, **kwargs):
        if pk:
            return super().get(request, *args, **kwargs)
        # List users only
        users = self.get_queryset()
        serializer = self.serializer_class(users, many=True)
        return Response(serializer.data)
    
    def put(self, request, pk=None, *args, **kwargs):
        return Response({'error': 'Update not allowed'}, status=405)
    
    def patch(self, request, pk=None, *args, **kwargs):
        return Response({'error': 'Update not allowed'}, status=405)


class CustomTokenObtainPairView(TokenObtainPairView):
    '''Custom token view'''
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        if email:
            try:
                user = get_user_model().objects.get(email=email)
                lockout_response = check_account_lockout(user)
                if lockout_response:
                    return lockout_response

                # Check if email verification is required
                if not user.is_email_verified:
                    return Response({
                        'requires_email_verification': True,
                        'message': 'Please verify your email first'
                    }, status=200)

            except get_user_model().DoesNotExist:
                pass
        response = super().post(request, *args, **kwargs)
        if response.status_code == 200 and 'access' in response.data:
            # Login successful, get user from email
            email = request.data.get('email')
            if email:
                try:
                    user = get_user_model().objects.get(email=email)
                    log_activity(user, 'login', request)
                except get_user_model().DoesNotExist:
                    pass
        return response


class LogoutView(APIView):
    '''Implements Logout Functionality'''
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = LogoutSerializer

    def post(self, request):
        try:
            log_activity(request.user, 'logout', request)
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
                log_activity(request.user, 'otp_request', request)

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

            with transaction.atomic():
                # Get fresh user instance and lock it
                user = get_user_model().objects.select_for_update().get(pk=request.user.pk)

                # Check if email is already in use by another user
                if get_user_model().objects.filter(email=new_email).exclude(id=user.id).exists():
                    return Response({'error': 'Email already in use by another account'}, status=400)

                is_valid, result = validate_otp(user, new_email, otp)
                if not is_valid:
                    return Response({'error': result}, status=429 if "Too many failed attempts" in result else 400)

                # OTP is valid, update email and verification status
                user.email = new_email
                user.is_email_verified = True
                user.save(update_fields=['email', 'is_email_verified'])
                log_activity(user, 'email_change', request)

                if result:
                    result.delete()  # Delete OTP record

                return Response({'success': 'Email verified and updated'}, status=200)

        return Response({'error': 'Invalid Request'}, status=400)


class PublicEmailVerify(APIView):
    '''View for verifying public email endpoints'''
    serializer_class = EmailOTPConfirmSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            new_email = serializer.validated_data['new_email']
            otp = serializer.validated_data['otp']

            # Find user by email and ensure atomic operation
            with transaction.atomic():
                try:
                    user = get_user_model().objects.select_for_update().get(email=new_email)
                except get_user_model().DoesNotExist:
                    return Response({'error': 'User not found'}, status=400)

                is_valid, result = validate_otp(user, new_email, otp)

                if not is_valid:
                    return Response({'error': result}, status=429 if "Too many failed attempts" in result else 400)

                # Only update if not already verified
                if not user.is_email_verified:
                    user.is_email_verified = True
                    user.save(update_fields=['is_email_verified'])
                    log_activity(user, 'otp_verify', request)

                if result:
                    result.delete()

                return Response({'success': 'Email verified.'}, status=200)
        return Response({'error': 'Invalid Request'}, status=400)


class PublicResendOTP(APIView):
    '''View for resending OTP without authentication'''

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email required'}, status=400)

        try:
            user = get_user_model().objects.get(email=email)
        except get_user_model().DoesNotExist:
            return Response({'error': 'User not found'}, status=400)

        generate_and_send_otp(
            user, email, subject="Verify Your Email", purpose="registration")
        log_activity(user, 'otp_request', request)
        return Response({'message': 'OTP sent successfully'}, status=200)


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
                with transaction.atomic():
                    # Get fresh user instance and lock it
                    user = get_user_model().objects.select_for_update().get(pk=request.user.pk)

                    if not user.check_password(old_pass):
                        return Response({'error': 'Incorrect Password.'}, status=400)
                    if check_password_reuse(user, new_pass):
                        return Response({'error': 'Please use password other than recent ones'}, status=400)

                    # Save old password to history
                    PasswordHistory.objects.create(
                        user=user,
                        password=user.password  # Current hashed password
                    )

                    user.set_password(new_pass)
                    # Only update password field
                    user.save(update_fields=['password'])
                    log_activity(user, 'password_change', request)

                    return Response({'success': 'Successfully Password Changed.'}, status=200)

            except Exception as e:
                return Response({'error': 'Something Went Wrong. Please try again later.'}, status=400)

        return Response({'error': 'Invalid Request'}, status=400)


class PublicThrottleTest(APIView):

    def get(self, request):
        return Response({'Success': f'Success for {request.user}'}, status=200)


class PrivateThrottleTest(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response({'Success': f'Success for {request.user}'}, status=200)


class Enable2FAA(APIView):
    '''API for Enabling 2FA Auth'''
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user

        if user.is_2fa_enabled:
            return Response({'error': '2FA already Enabled'}, status=400)

        try:
            with transaction.atomic():
                # Get fresh user instance and lock it
                user = get_user_model().objects.select_for_update().get(pk=user.pk)

                # Double check 2FA not enabled after lock
                if user.is_2fa_enabled:
                    return Response({'error': '2FA already Enabled'}, status=400)

                secret = pyotp.random_base32()

                # Only save secret, don't enable 2FA yet
                user.totp_secret = secret
                user.save(update_fields=['totp_secret'])

                totp_uri = pyotp.TOTP(secret).provisioning_uri(
                    name=user.email,
                    issuer_name="<Your Organization>"
                )

            qr = qrcode.make(totp_uri)
            buffer = io.BytesIO()
            qr.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode()

            return Response({'qr_code': img_str,
                            'message': 'Scan this QR code with Google Authenticator'}, status=200)

        except Exception:
            return Response({'error': 'Failed to enable 2FA'}, status=500)


class Verify2FA(APIView):
    '''View to confirm 2FA Auth'''
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = Verify2FASerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        user = request.user

        if not user.totp_secret:
            return Response({'error': '2FA setup not initiated.'}, status=400)

        if serializer.is_valid():
            otp = serializer.validated_data['otp']

            try:
                with transaction.atomic():
                    # Get fresh user instance and lock it
                    user = get_user_model().objects.select_for_update().get(pk=user.pk)

                    # Recheck TOTP secret exists after lock
                    if not user.totp_secret:
                        return Response({'error': '2FA setup not initiated.'}, status=400)

                    # Check if 2FA was enabled after lock
                    if user.is_2fa_enabled:
                        return Response({'error': '2FA already enabled.'}, status=400)

                    totp = pyotp.TOTP(user.totp_secret)
                    if totp.verify(otp, valid_window=1):
                        # Enable 2FA only after successful verification
                        user.is_2fa_enabled = True
                        user.save(update_fields=['is_2fa_enabled'])
                        log_activity(user, '2fa_enable', request)
                        return Response({"success": "2FA enabled successfully."}, status=status.HTTP_200_OK)
                    else:
                        return Response({"error": "Invalid or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)

            except Exception:
                return Response({"error": "Invalid or expired OTP."}, status=status.HTTP_400_BAD_REQUEST)

        else:
            return Response(serializer.errors, status=400)


class Cancel2FASetupView(APIView):
    '''Cancel incomplete 2FA setup'''
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user

        # Only clear if 2FA is not fully enabled
        if not user.is_2fa_enabled and user.totp_secret:
            user.totp_secret = None
            user.save()
            return Response({'success': '2FA setup cancelled'}, status=200)

        return Response({'message': 'No incomplete 2FA setup found'}, status=200)


class UnblockUserView(APIView):
    '''Admin/Superadmin View for unblocking user'''
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UnblockUserSerializer

    def check_permissions(self, request):
        super().check_permissions(request)
        if request.user.role not in ['admin', 'superadmin']:
            raise PermissionDenied('Admin or SuperAdmin role required')

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            with transaction.atomic():
                user = get_user_model().objects.select_for_update().get(
                    email=serializer.validated_data['email'])
                user.is_blocked = False
                user.save(update_fields=['is_blocked'])
                log_activity(user, 'account_unblock', request)
                return Response({'success': f'Successfully Unblocked User with E-Mail {user.email}'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': f'Error:{str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasswordResetRequest(APIView):
    '''APIView for password reset'''
    serializer_class = PasswordResetSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.get_user()

        uid = urlsafe_base64_encode(force_bytes(user.pk))

        token = default_token_generator.make_token(user)

        # Use frontend URL from request data
        frontend_url = request.data.get('reset_url', '')
        if not frontend_url:
            return Response({'error': 'reset_url is required'}, status=400)

        # Ensure URL includes /static/ and ends with .html
        frontend_url = frontend_url.rstrip('/')
        if not frontend_url.endswith('.html'):
            frontend_url += '/static/reset-password.html'
        elif '/static/' not in frontend_url:
            frontend_url = frontend_url.replace(
                'reset-password.html', 'static/reset-password.html')

        # Construct URL with query parameters for frontend
        reset_link = f"{frontend_url}?uid={uid}&token={token}"

        send_mail(
            subject='Password Reset',
            message=f"Your Personal Password Reset Link is {reset_link}. \nIt will expire in 10 minutes. \nDo not share it with anyone\n",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        return Response({'success': 'Successfully sent password reset link.'}, status=200)


class PasswordResetConfirm(APIView):
    '''View for confirming password reset'''
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            print(serializer.errors)
            return Response(serializer.errors, status=400)
        try:
            uid = serializer.validated_data['uid']
            new_password = serializer.validated_data['new_password']
            print(uid, new_password)

            with transaction.atomic():

                user = get_user_model().objects.select_for_update().get(pk=uid)

                if check_password_reuse(user, new_password):
                    return Response(
                        {'error': 'Please use a password different from your recent ones'},
                        status=400
                    )

                # Save old password in history
                PasswordHistory.objects.create(
                    user=user, password=user.password)

                # Set new password
                user.set_password(new_password)
                user.save(update_fields=['password'])

                return Response({'success': "Password Reset Successful."}, status=200)

        except Exception as e:
            print("Exception in PasswordResetConfirm:", e)  # <- Add this
            return Response({'error': "Something went wrong"}, status=500)


class SendPhoneOTPView(APIView):
    '''View to send OTP to phone'''
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        phone = request.data.get('phone')

        if not phone:
            return Response({'detail': 'Phone number is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = get_user_model().objects.get(phone=phone)
        except get_user_model().DoesNotExist:
            return Response({'detail': 'Phone number not registered.'}, status=status.HTTP_400_BAD_REQUEST)

        if user.is_blocked:
            return Response({'detail': 'User is blocked. Contact support.'}, status=status.HTTP_403_FORBIDDEN)

        try:
            generate_and_send_sms_otp(phone)
            log_activity(user, 'otp_request', request)
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        return Response({'detail': 'OTP sent successfully.'}, status=status.HTTP_200_OK)


class ConfirmPhoneOTPView(APIView):
    '''APIView for phone OTP verification'''
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = PhoneOTPVerifySerializer

    def post(self, request):
        serializer = self.serializer_class(
            data=request.data,
            context={'phone': request.data.get('phone')}
        )
        serializer.is_valid(raise_exception=True)

        try:
            with transaction.atomic():
                user = get_user_model().objects.select_for_update().get(
                    phone=serializer.validated_data['phone']
                )

                if user != request.user:
                    return Response({'detail': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

                if user.is_blocked:
                    return Response({'detail': 'User Blocked. Contact Support.'}, status=status.HTTP_423_LOCKED)

                user.is_phone_verified = True
                user.save(update_fields=['is_phone_verified'])
                log_activity(user, 'otp_verify', request)

                return Response({'success': 'Phone Verified Successfully.'}, status=status.HTTP_200_OK)

        except get_user_model().DoesNotExist:
            return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GoogleConfigView(APIView):
    '''API endpoint to serve Google OAuth configuration to frontend'''

    def get(self, request):
        client_id = getattr(settings, 'GOOGLE_OAUTH2_CLIENT_ID', '')
        configured = bool(client_id and client_id.strip())

        return Response({
            'client_id': client_id if configured else 'demo-client-id',
            'configured': configured,
            'demo_mode': not configured
        })


class GoogleLoginView(APIView):
    '''Login APIView for google login'''

    def post(self, request):
        access_token = request.data.get('access_token')
        if not access_token:
            return Response({
                'error': 'Google access token is required to continue',
                'message': 'Please provide a valid Google access token'
            }, status=400)

        try:
            response = requests.get(
                f'https://www.googleapis.com/oauth2/v2/userinfo?access_token={access_token}',
                timeout=10
            )
            if response.status_code != 200:
                return Response({
                    'error': 'Google authentication failed',
                    'message': 'The provided access token is invalid or expired. Please try signing in with Google again.'
                }, status=400)

            data = response.json()

            # Validate required fields
            if 'email' not in data or 'id' not in data:
                return Response({
                    'error': 'Incomplete Google profile',
                    'message': 'Your Google account is missing required information. Please ensure your Google account has an email address.'
                }, status=400)

            with transaction.atomic():
                try:
                    user = get_user_model().objects.select_for_update().get(
                        email=data['email'])

                    # Check if user is blocked before proceeding
                    if user.is_blocked:
                        return Response({
                            'error': 'Account blocked',
                            'message': 'Your account has been blocked. Please contact support for assistance.'
                        }, status=423)

                    from allauth.socialaccount.models import SocialAccount
                    SocialAccount.objects.get_or_create(
                        user=user, provider='google', defaults={'uid': data['id']}
                    )
                except get_user_model().DoesNotExist:
                    user = get_user_model().objects.create_user(
                        email=data['email'],
                        fname=data.get('given_name', ''),
                        lname=data.get('family_name', ''),
                        phone='',
                        is_email_verified=True
                    )
                    from allauth.socialaccount.models import SocialAccount
                    SocialAccount.objects.create(
                        user=user,
                        provider='google',
                        uid=data['id']
                    )

                lockout_response = check_account_lockout(user)
                if lockout_response:
                    return lockout_response

                refresh = RefreshToken.for_user(user)
                log_activity(user, 'login', request)
                return Response({
                    'success': True,
                    'message': 'Successfully signed in with Google',
                    'access': str(refresh.access_token),
                    'refresh': str(refresh)
                })

        except requests.exceptions.Timeout:
            return Response({
                'error': 'Connection timeout',
                'message': 'Google authentication timed out. Please check your internet connection and try again.'
            }, status=400)
        except requests.exceptions.ConnectionError:
            return Response({
                'error': 'Connection failed',
                'message': 'Unable to connect to Google services. Please check your internet connection and try again.'
            }, status=400)
        except (ValueError, KeyError):
            return Response({
                'error': 'Invalid response from Google',
                'message': 'Received invalid data from Google. Please try signing in again.'
            }, status=400)
        except Exception:
            return Response({
                'error': 'Authentication failed',
                'message': 'An unexpected error occurred during Google sign-in. Please try again.'
            }, status=400)


class ActivityLogView(APIView):
    '''Admin view to get any user's activity log by email'''
    permission_classes = [
        permissions.IsAuthenticated, custom_permissions.IsAdmin]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=400)

        try:
            user = get_user_model().objects.get(email=email)
        except get_user_model().DoesNotExist:
            return Response({'error': 'User not found'}, status=404)

        from core.models import ActivityLog
        logs = ActivityLog.objects.filter(user=user)[:20]
        data = [{
            'action': log.get_action_display(),
            'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'ip_address': log.ip_address or 'Unknown',
            'location': log.location or 'Unknown',
            'device': log.user_device[:50] + '...' if len(log.user_device) > 50 else log.user_device
        } for log in logs]
        return Response({
            'user': f"{user.get_full_name} ({user.email})",
            'logs': data
        })


class SystemStatsView(APIView):
    '''APIView for system stats'''
    permission_classes = [permissions.IsAuthenticated, custom_permissions.IsAdmin]

    def get(self,request):
        total_users = get_user_model().objects.count()
        active_users = get_user_model().objects.filter(is_active=True).count()
        blocked_users = get_user_model().objects.filter(is_blocked=True).count()
        total_social_accounts = SocialAccount.objects.count()
        total_2fa_enabled = get_user_model().objects.filter(is_2fa_enabled=True).count()
        total_email_verified = get_user_model().objects.filter(is_email_verified=True).count()
        total_phone_verified = get_user_model().objects.filter(is_phone_verified=True).count()
        return Response({
            'total_users': total_users,
            'active_users': active_users,
            'blocked_users': blocked_users,
            'total_social_accounts': total_social_accounts,
            'total_2fa_enabled': total_2fa_enabled,
            'total_email_verified': total_email_verified,
            'total_phone_verified': total_phone_verified
        }, status=200)
