from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView
app_name = 'user'
urlpatterns = [
    path('create/', views.CreateUserView.as_view(), name='create'),
    path('me/', views.UpdateUserView.as_view(), name='me'),
    path('token/', views.CustomTokenObtainPairView.as_view(), name='token'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('admin/',views.AdminUserView.as_view(),name='admin'),
    path('superadmin/',views.SuperAdminUserView.as_view(),name='superadmin'),
    path('logout/',views.LogoutView.as_view(),name='logout'),
    path('request-email-otp/', views.RequestEmailOTPView.as_view(), name='request-email-otp'),
    path('verify-email-otp/', views.ConfirmEmailOTPView.as_view(), name='verify-email-otp'),
    path('public_test-throttle',views.PublicThrottleTest.as_view(),name='public_throttle_test'),
    path('private_test-throttle', views.PrivateThrottleTest.as_view(), name='private_throttle_test'),
    path('password_change_with_old_password',views.PasswordChangeWithOldPasswordView.as_view(),name="passchange"),
    path('enable_2fa',views.Enable2FAA.as_view(),name='enable_2fa'),
    path('verify_2fa',views.Verify2FA.as_view(),name='verify_2fa'),
    path('login_2fa',views.Login2FA.as_view(),name='login_2fa'),
    path('unblock_user',views.UnblockUserView.as_view(),name='unblock_user'),
    


]
