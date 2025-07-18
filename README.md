# Auth App - Comprehensive Authentication System

A robust Django-based authentication system designed for plug-and-play integration via RESTful API endpoints. This project provides a complete authentication solution with role-based access control, email verification, and JWT-based security.

## Features

### Core Authentication
- **JWT-based Authentication**: Secure token-based authentication using Django REST Framework and SimpleJWT with token refresh and blacklisting
- **Role-based Access Control (RBAC)**: Predefined roles (superadmin, admin, moderator, user) with appropriate permissions and access levels
- **User Registration & Login**: Complete user registration flow with email verification and secure login process

### Security Features
- **Email Verification**: OTP-based email verification system with expiration and attempt tracking
- **Token Management**: Token refresh, blacklisting, and rotation for enhanced security with configurable lifetimes
- **Rate Limiting**: Protection against brute force attacks with attempt tracking and lockout mechanisms
- **Secure Password Handling**: Password validation with minimum length requirements and confirmation checks

### User Management
- **Profile Management**: Comprehensive user profile with personal details, preferences, and security settings
- **Role-based Administration**: Different access levels for user management with appropriate permissions
- **Email Change Verification**: Secure email change process with OTP verification and rate limiting
- **User Activity Tracking**: Monitoring of login attempts, IP addresses, and device information

### API Documentation
- **OpenAPI/Swagger**: Automatic API documentation using drf-spectacular with interactive testing interface

## Project Structure

```
auth-app/
├── Authentication_App/       # Main Django project directory
│   ├── settings.py          # Project settings including JWT configuration
│   ├── urls.py              # Main URL routing
│   └── ...
├── core/                    # Core application with user models
│   ├── models.py            # CustomUser and EmailOTP models
│   ├── admin.py             # Admin panel configuration
│   ├── management/          # Custom management commands
│   │   └── commands/
│   │       └── wait_for_db.py  # Command to wait for database connection
│   └── tests/               # Core model tests
├── user/                    # User API application
│   ├── serializers.py       # API serializers for user operations
│   ├── views.py             # API views for authentication and user management
│   ├── urls.py              # API endpoint routing
│   ├── permissions.py       # Custom permission classes
│   ├── utils.py             # Utility functions for OTP handling
│   └── tests/               # API tests
└── docker/                  # Docker configurations
    └── postgres/            # PostgreSQL Docker setup
```

## Tech Stack

- **Backend Framework**: Django 5.2.4
- **API Framework**: Django REST Framework 3.16.0
- **Authentication**: JWT (djangorestframework-simplejwt 5.5.0)
- **Database**: PostgreSQL
- **Documentation**: drf-spectacular 0.28.0
- **Dependency Management**: Poetry
- **Development Environment**: Docker for local PostgreSQL
- **Environment Management**: python-decouple for configuration
- **Database URL Handling**: dj-database-url
- **Image Processing**: Pillow 11.3.0 (for profile pictures)

## Data Models

### CustomUser Model

Extends Django's AbstractBaseUser with the following fields:

- **Authentication Fields**: email (username), password
- **Personal Information**: fname, lname, phone, dob, gender, bio, profile_pic
- **Address Information**: address, city, state, country, postal_code
- **Permission Fields**: is_active, is_staff, is_blocked, role
- **Verification Status**: is_email_verified, is_phone_verified, is_2fa_enabled
- **Security Tracking**: last_ip, last_device, last_login_location, failed_login_attempts
- **Preferences**: language, timezone, prefers_dark_mode
- **Audit Fields**: created_at, updated_at, deleted_at

### EmailOTP Model

Stores OTP information for email verification:

- **Relationship**: ForeignKey to CustomUser
- **Verification Data**: new_email, otp
- **Security**: attempts (tracks failed attempts)
- **Timestamps**: created_at (for expiration checking)

## API Endpoints

### Authentication
- `POST /api/user/create/` - Register a new user
  - Accepts: email, password, password2, fname, lname, phone
  - Returns: User details (excluding password)
  - Triggers: Email verification OTP

- `POST /api/user/token/` - Obtain JWT token pair
  - Accepts: email, password
  - Returns: access token, refresh token

- `POST /api/user/token/refresh/` - Refresh JWT token
  - Accepts: refresh token
  - Returns: new access token, new refresh token

- `POST /api/user/logout/` - Logout (blacklist token)
  - Accepts: refresh token
  - Action: Blacklists the token to prevent reuse

### User Management
- `GET/PATCH /api/user/me/` - View/update current user profile
  - GET: Returns user profile details
  - PATCH: Updates user profile (except email and password)

- `GET/PUT/DELETE /api/user/admin/` - Admin user management
  - Requires: Admin role
  - Access: All users except superadmins and admins

- `GET/PUT/DELETE /api/user/superadmin/` - Super admin user management
  - Requires: Superadmin role
  - Access: All users

### Email Verification
- `POST /api/user/request-email-otp/` - Request email change OTP
  - Accepts: new_email
  - Validation: Rate limiting (max 3 requests per hour)
  - Action: Sends OTP to new email

- `POST /api/user/verify-email-otp/` - Verify email with OTP
  - Accepts: new_email, otp
  - Validation: OTP correctness, expiration (10 minutes), max attempts (5)
  - Action: Updates user email and marks as verified

## Security Features

### JWT Configuration

```python
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'AUTH_HEADER_TYPES': ('Bearer',),
    'BLACKLIST_AFTER_ROTATION': True,
    'ROTATE_REFRESH_TOKENS': True,
}
```

### OTP Security

- **Generation**: Secure random 6-digit OTP
- **Expiration**: 10-minute validity period
- **Rate Limiting**: Maximum 3 OTP requests per hour
- **Attempt Tracking**: Maximum 5 verification attempts per OTP

### Password Validation

- Minimum length: 5 characters
- Password confirmation check
- Django's built-in password validators:
  - UserAttributeSimilarityValidator
  - MinimumLengthValidator
  - CommonPasswordValidator
  - NumericPasswordValidator

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

Option 1: Using docker run command:
```bash
docker run --name auth_pg \
  -e POSTGRES_DB=auth_db \
  -e POSTGRES_USER=auth_user \
  -e POSTGRES_PASSWORD=auth_pass \
  -p 5432:5432 \
  -d postgres:15
```

Option 2: Using docker-compose (for testing database):
```bash
cd docker/postgres
docker-compose up -d
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

### 5. Wait for Database and Apply Migrations

```bash
poetry shell
python manage.py wait_for_db  # Custom command to ensure database is ready
python manage.py migrate
```

### 6. Create Superuser (Optional)

```bash
python manage.py createsuperuser
```

### 7. Run Development Server

```bash
python manage.py runserver
```

### 8. Access API Documentation

Once the server is running, you can access the API documentation at:
```
http://localhost:8000/api/docs/
```

## Testing

The project includes comprehensive test coverage for models, API endpoints, and utility functions.

### Running Tests

```bash
python manage.py test
```

### Test Coverage

- **Model Tests**: Tests for CustomUser and EmailOTP models
- **API Tests**: Tests for all API endpoints including authentication, user management, and email verification
- **Utility Tests**: Tests for OTP generation, validation, and email sending

## Current Development Status

The project is in active development with the following components completed:

### Completed Features
- ✅ Core user authentication system with JWT
- ✅ Custom user model with extended profile fields
- ✅ Role-based access control (superadmin, admin, moderator, user)
- ✅ Email OTP verification system with security features
- ✅ User profile management API
- ✅ Token refresh and blacklisting
- ✅ API documentation with Swagger
- ✅ Comprehensive test suite

## Next Steps

### Planned Features
- ⏳ Password reset functionality
- ⏳ Two-factor authentication (2FA)
- ⏳ Phone number verification via SMS
- ⏳ Account lockout after failed login attempts
- ⏳ Frontend integration examples
- ⏳ Social authentication (OAuth)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

