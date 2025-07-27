from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from .models import CustomUser, EmailOTP, PasswordHistory


@admin.register(CustomUser)
class CustomUserAdmin(BaseUserAdmin):
    model = CustomUser
    ordering = ['email']

    list_display = (
        'email', 'username', 'fname', 'lname', 'phone',
        'role', 'is_active', 'is_staff', 'is_superuser',
        'is_blocked', 'is_email_verified', 'is_phone_verified', 'is_2fa_enabled',
    )

    list_filter = (
        'is_active', 'is_staff', 'is_superuser',
        'is_blocked', 'is_email_verified', 'is_phone_verified',
        'is_2fa_enabled', 'role', 'gender', 'language', 'prefers_dark_mode',
    )

    search_fields = ('email', 'fname', 'lname', 'username', 'phone', 'city', 'state', 'country')

    readonly_fields = ('created_at', 'updated_at', 'last_login', 'deleted_at')

    fieldsets = (
        (_('Authentication Info'), {
            'fields': ('email', 'password')
        }),
        (_('Personal Info'), {
            'fields': (
                'username', 'fname', 'lname', 'phone',
                'dob', 'gender', 'bio', 'profile_pic',
                'address', 'city', 'state', 'country', 'postal_code'
            )
        }),
        (_('Security & Device Info'), {
            'fields': (
                'last_ip', 'last_device', 'last_login_location',
                'failed_login_attempts', 'last_failed_login'
            )
        }),
        (_('Preferences'), {
            'fields': (
                'language', 'timezone', 'prefers_dark_mode'
            )
        }),
        (_('Permissions'), {
            'fields': (
                'is_active', 'is_staff', 'is_superuser',
                'is_blocked', 'is_email_verified', 'is_phone_verified',
                'is_2fa_enabled', 'role', 'groups', 'user_permissions'
            )
        }),
        (_('Audit Info'), {
            'fields': (
                'last_login', 'created_at', 'updated_at', 'deleted_at'
            )
        }),
    )

    add_fieldsets = (
        (_('Create New User'), {
            'classes': ('wide',),
            'fields': (
                'email', 'password1', 'password2',
                'fname', 'lname', 'phone', 'role',
                'is_active', 'is_staff', 'is_superuser'
            ),
        }),
    )


@admin.register(EmailOTP)
class EmailOTPAdmin(admin.ModelAdmin):
    list_display = ('user', 'new_email', 'otp', 'attempts', 'created_at')
    list_filter = ('created_at',)
    search_fields = ('user__username', 'new_email', 'otp')
    readonly_fields = ('created_at',)

@admin.register(PasswordHistory)
class PasswordHistoryAdmin(admin.ModelAdmin):
    list_display = ('user', 'changed_at')
    list_filter = ('changed_at',)
    search_fields = ('user__email',)
    readonly_fields = ('changed_at',)