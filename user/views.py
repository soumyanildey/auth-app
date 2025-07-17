from rest_framework import generics, permissions, status
from .serializers import UserSerializer,CustomTokenObtainPairSerializer,LogoutSerializer
from rest_framework.settings import api_settings
from . import permissions as custom_permissions
from django.contrib.auth import get_user_model,logout
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework.views import APIView


class CreateUserView(generics.CreateAPIView):
    '''Viewset for handling the create user serializer'''
    serializer_class = UserSerializer

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
    permission_classes = [permissions.IsAuthenticated,custom_permissions.IsAdmin]
    queryset = get_user_model().objects.exclude(role__in=['superadmin', 'admin'])


class SuperAdminUserView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated, custom_permissions.IsSuperAdmin]
    queryset = get_user_model().objects.all()
    lookup_field = 'pk'


class CustomTokenObtainPairView(TokenObtainPairView):
    '''Custom token view'''
    serializer_class = CustomTokenObtainPairSerializer



class LogoutView(APIView):
    '''Implements Logout Functionality'''
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = LogoutSerializer
    def post(self,request):
        try :
            logout(request)
            refresh_token = request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception:
            return Response(status=status.HTTP_400_BAD_REQUEST)