from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from datetime import timedelta
import uuid
import datetime
from Authentication_App.settings import AUTH_USER_MODEL


class CustomUserManager(BaseUserManager):
    '''User Model Manager'''

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Users must have an email address")
        user = self.model(email=self.normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        user = self.create_user(email, password, **extra_fields)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

    def get_by_natural_key(self, email):
        return self.get(email=email)


def save_password_to_history(user):
    if not user.pk:
        return

    # Save the new password to history
    PasswordHistory.objects.create(user=user, password=user.password)

    # Keep only the 10 most recent entries
    recent_ids = PasswordHistory.objects.filter(
        user=user
    ).order_by('-changed_at').values_list('id', flat=True)[:10]

    PasswordHistory.objects.filter(user=user).exclude(id__in=recent_ids).delete()



class CustomUser(AbstractBaseUser, PermissionsMixin):
    '''User Model'''

    email = models.EmailField(unique=True)
    username = models.CharField(
        max_length=150, unique=True, blank=True, null=True)
    fname = models.CharField(max_length=150)
    lname = models.CharField(max_length=150)
    phone = models.CharField(max_length=20)

    dob = models.DateField(null=True, blank=True)
    gender = models.CharField(null=True, blank=True, choices=[
        ('male', 'Male'),
        ('female', 'Female'),
        ('other', 'Other')
    ],
        max_length=20)
    bio = models.TextField(blank=True)
    profile_pic = models.ImageField(
        upload_to='profiles/', blank=True, null=True)
    address = models.TextField(blank=True)
    city = models.CharField(max_length=100, blank=True)
    state = models.CharField(max_length=100, blank=True)
    country = models.CharField(max_length=100, blank=True)
    postal_code = models.CharField(max_length=20, blank=True)

    # Permissions
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_blocked = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    is_phone_verified = models.BooleanField(default=False)
    is_2fa_enabled = models.BooleanField(default=False)

    # Security & Devices
    last_ip = models.GenericIPAddressField(null=True, blank=True)
    last_device = models.CharField(max_length=255, blank=True)
    last_login_location = models.CharField(max_length=255, blank=True)
    failed_login_attempts = models.IntegerField(default=0)
    last_failed_login = models.DateTimeField(null=True, blank=True)
    totp_secret = models.CharField(max_length=32,blank=True,null=True)

    # Preferences
    language = models.CharField(max_length=20, default="en")
    timezone = models.CharField(max_length=50, default="UTC")
    prefers_dark_mode = models.BooleanField(default=False)

    # Audit
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True)

    role = models.CharField(max_length=30, choices=[
        ("superadmin", "Super Admin"),
        ("admin", "Admin"),
        ("moderator", "Moderator"),
        ("user", "User"),
    ], default="user")

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ['fname', 'lname', 'phone']

    objects = CustomUserManager()

    def __str__(self):
        return self.email

    @property
    def get_full_name(self):
        return self.fname + " " + self.lname

    def save(self, *args, **kwargs):
        is_new = self.pk is None
        old_password = None

        if not is_new:
            old_user = CustomUser.objects.get(pk=self.pk)
            old_password = old_user.password

        super().save(*args, **kwargs)

        if is_new or (old_password and old_password != self.password):
            save_password_to_history(self)


class EmailOTP(models.Model):
    '''Model for Email OTP Verification'''
    user = models.ForeignKey(AUTH_USER_MODEL, on_delete=models.CASCADE)
    new_email = models.EmailField()
    otp = models.CharField(max_length=6)
    attempts = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_otp_expired(self):
        return timezone.now() > self.created_at + datetime.timedelta(minutes=10)

    class Meta:
        ordering = ['-created_at']


class PasswordHistory(models.Model):
    '''Model for password history tracking'''
    user = models.ForeignKey(AUTH_USER_MODEL, on_delete=models.CASCADE)
    password = models.CharField(max_length=255)
    changed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-changed_at']

    def __str__(self):
        return f"Password Changed for {self.user} at {self.changed_at}"
