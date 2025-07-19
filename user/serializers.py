from rest_framework import serializers
from django.utils.translation import gettext as _
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class UserSerializer(serializers.ModelSerializer):
    '''User API Serializers'''
    password2 = serializers.CharField(write_only=True, min_length=5)

    class Meta:
        model = get_user_model()
        fields = ['email', 'password', 'password2', 'fname', 'lname', 'phone']
        extra_kwargs = {'password': {'write_only': True, 'min_length': 5}}

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

        if value.isdigit() == False:
            raise serializers.ValidationError(
                _('Phone number must be digits only!'))

        if len(value) < 7 or len(value) > 15:
            raise serializers.ValidationError(_('Invalid phone number!'))

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

    def validate(self, attrs):
        data = super().validate(attrs)
        return data


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()


class EmailOTPRequestSerializer(serializers.Serializer):
    new_email = serializers.EmailField()


class EmailOTPConfirmSerializer(serializers.Serializer):
    new_email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
