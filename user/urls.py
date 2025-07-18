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


]
