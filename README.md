# Auth App - Comprehensive Authentication System

A robust Django-based authentication system designed for plug-and-play integration via RESTful API endpoints. This project provides a complete authentication solution with role-based access control, email verification, and JWT-based security.

## Features

### Core Authentication
- **JWT-based Authentication**: Secure token-based authentication using Django REST Framework and SimpleJWT
- **Role-based Access Control (RBAC)**: Predefined roles (superadmin, admin, moderator, user) with appropriate permissions
- **User Registration & Login**: Complete user registration flow with email verification

### Security Features
- **Email Verification**: OTP-based email verification system
- **Token Management**: Token refresh, blacklisting, and rotation for enhanced security
- **Rate Limiting**: Protection against brute force attacks with attempt tracking

### User Management
- **Profile Management**: Comprehensive user profile with personal details
- **Role-based Administration**: Different access levels for user management
- **Email Change Verification**: Secure email change process with OTP verification

### API Documentation
- **OpenAPI/Swagger**: Automatic API documentation using drf-spectacular

## Tech Stack

- **Backend**: Django 5.2.4, Django REST Framework
- **Authentication**: JWT (djangorestframework-simplejwt)
- **Database**: PostgreSQL
- **Documentation**: drf-spectacular
- **Dependency Management**: Poetry
- **Development Environment**: Docker for local PostgreSQL

## API Endpoints

### Authentication
- `POST /api/user/create/` - Register a new user
- `POST /api/user/token/` - Obtain JWT token pair
- `POST /api/user/token/refresh/` - Refresh JWT token
- `POST /api/user/logout/` - Logout (blacklist token)

### User Management
- `GET/PATCH /api/user/me/` - View/update current user profile
- `GET/PUT/DELETE /api/user/admin/` - Admin user management
- `GET/PUT/DELETE /api/user/superadmin/` - Super admin user management

### Email Verification
- `POST /api/user/request-email-otp/` - Request email change OTP
- `POST /api/user/verify-email-otp/` - Verify email with OTP

## Project Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/auth-app.git
cd auth-app
```

### 2. Install Dependencies using Poetry

```bash
poetry install
```

### 3. Run PostgreSQL Locally via Docker

```bash
docker run --name auth_pg \
  -e POSTGRES_DB=auth_db \
  -e POSTGRES_USER=auth_user \
  -e POSTGRES_PASSWORD=auth_pass \
  -p 5432:5432 \
  -d postgres:15
```

### 4. Create `.env` File

```ini
# .env
DEBUG=True
SECRET_KEY=your-django-secret-key
DATABASE_URL=postgres://auth_user:auth_pass@localhost:5432/auth_db

EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your@email.com
EMAIL_HOST_PASSWORD=email-password
DEFAULT_FROM_EMAIL=your@email.com

# For testing
TEST_DB_NAME=test_db
TEST_DB_USER=test_user
TEST_DB_PASSWORD=test_pass
TEST_DB_HOST=localhost
TEST_DB_PORT=5432
```

### 5. Apply Migrations & Run Server

```bash
poetry shell
python manage.py migrate
python manage.py runserver
```

### 6. Access API Documentation

Once the server is running, you can access the API documentation at:
```
http://localhost:8000/api/docs/
```

## Current Development Status

The project is in active development with the following components completed:
- Core user authentication system
- JWT token implementation
- Role-based access control
- Email OTP verification system
- User profile management
- API documentation with Swagger

## Next Steps

- Password reset functionality
- Two-factor authentication (2FA)
- Phone number verification
- Enhanced security features
- Frontend integration examples

