from rest_framework import serializers
from django.utils.translation import gettext as _
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.utils import timezone
import pyotp
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator


class UserSerializer(serializers.ModelSerializer):
    '''User API Serializers'''
    password2 = serializers.CharField(write_only=True, min_length=5)

    class Meta:
        model = get_user_model()
        fields = [
            'email', 'password', 'password2', 'fname', 'lname', 'phone',
            'dob', 'gender', 'bio', 'profile_pic', 'address', 'city', 'state', 'country', 'postal_code',
            'role', 'is_2fa_enabled',
            'is_email_verified', 'is_phone_verified', 'created_at', 'updated_at'
        ]

        extra_kwargs = {
            'password': {'write_only': True, 'min_length': 5},
            'created_at': {'read_only': True},
            'updated_at': {'read_only': True},
            'role': {'read_only': True},
            'is_email_verified': {'read_only': True},
            'is_phone_verified': {'read_only': True},
            'is_2fa_enabled': {'read_only': True},
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance:
            self.fields['email'].read_only = True
            self.fields['password'].read_only = True
            self.fields['password2'].read_only = True

    def validate_email(self, value):
        if get_user_model().objects.filter(email=value).exists():
            raise serializers.ValidationError(
                _('This email is already registered.'))
        return value

    def validate_phone(self, value):
        if not value:  # Allow empty phone
            return value

        if not value.isdigit():
            raise serializers.ValidationError(
                _('Phone number must be digits only!'))

        if len(value) < 7 or len(value) > 15:
            raise serializers.ValidationError(_('Invalid phone number!'))

        # Check for duplicates only if phone is being changed
        if self.instance and self.instance.phone == value:
            return value

        if get_user_model().objects.filter(phone=value).exists():
            raise serializers.ValidationError(
                _('This phone number is already registered.'))

        return value

    def validate(self, data):
        if self.instance:
            # Check if tampered input tries to update password/email
            if 'email' in self.initial_data:

                raise serializers.ValidationError(
                    {'email': _('Email update is not allowed here.')})

            if 'password' in self.initial_data or 'password2' in self.initial_data:

                raise serializers.ValidationError(
                    {'password': _('Password update is not allowed here.')})
        else:
            # Create mode: validate passwords match
            password = data.get('password')
            password2 = data.get('password2')

            if password != password2:
                raise serializers.ValidationError(
                    {'password2': _('Passwords do not match!')})

        return data

    def create(self, validated_data):
        '''Creates the user object and return it with encrypted password'''
        validated_data.pop('password2', None)

        return get_user_model().objects.create_user(**validated_data)

    def update(self, instance, validated_data):
        '''Update user object instance'''

        user = super().update(instance, validated_data)

        return user


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    '''Custom token serializer'''

    username_field = get_user_model().USERNAME_FIELD
    otp = serializers.CharField(required=False, allow_blank=True)

    def validate_otp(self, value):
        if value:
            value = value.strip()
            if not value.isdigit():
                raise serializers.ValidationError(
                    'OTP must contain numbers only')
            value = value.zfill(6)
            if len(value) != 6:
                raise serializers.ValidationError('OTP must be 6 digits')
        return value

    def validate(self, attrs):
        otp = attrs.pop('otp', None)

        try:
            # First validate credentials
            data = super().validate(attrs)
            if self.user.failed_login_attempts > 0:
                self.user.failed_login_attempts = 0
                self.user.save()

            # Check if user has 2FA enabled
            if self.user.is_2fa_enabled:
                if not otp:
                    return {
                        'requires_2fa': True,
                        'message': '2FA verification required',
                    }
                totp = pyotp.TOTP(self.user.totp_secret)
                if not totp.verify(otp, valid_window=1):
                    raise serializers.ValidationError('Invalid 2FA OTP')
            return data
        except Exception:
            email = attrs.get('email')
            if email:
                try:
                    user = get_user_model().objects.get(email=email)
                    user.failed_login_attempts += 1
                    user.last_failed_login = timezone.now()
                    if user.failed_login_attempts >= 5:
                        user.is_blocked = True
                    user.save()
                except get_user_model().DoesNotExist:
                    pass
            raise


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class EmailOTPRequestSerializer(serializers.Serializer):
    new_email = serializers.EmailField()


class EmailOTPConfirmSerializer(serializers.Serializer):
    new_email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)


class PasswordChangeWithOldPasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, min_length=5)
    new_password = serializers.CharField(write_only=True, min_length=5)


class Verify2FASerializer(serializers.Serializer):
    otp = serializers.CharField(required=True)

    def validate_otp(self, value):
        # Remove any whitespace
        value = value.strip()

        # Check if it's numeric
        if not value.isdigit():
            raise serializers.ValidationError('OTP must contain only digits')

        # Pad with leading zeros if needed (TOTP codes are 6 digits)
        value = value.zfill(6)

        # Check length after padding
        if len(value) != 6:
            raise serializers.ValidationError('OTP must be 6 digits')

        return value


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate(self, attrs):
        email = attrs.get('email')

        try:
            self.user = get_user_model().objects.get(email=email)
        except get_user_model().DoesNotExist:
            raise serializers.ValidationError(
                'User Email does not exist.')

        return attrs

    def get_user(self):

        return self.user


class PasswordResetConfirmSerializer(serializers.Serializer):
    '''Serializer for confirming the reset password link'''
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, min_length=5)

    def validate(self, attrs):

        try:
            uid = urlsafe_base64_decode(attrs['uid']).decode()
            attrs['uid'] = uid
            user = get_user_model().objects.get(pk=uid)
        except Exception:
            raise serializers.ValidationError('Invalid user')

        if not default_token_generator.check_token(user, attrs['token']):
            raise serializers.ValidationError('Invalid or Expired Token')

        return attrs
