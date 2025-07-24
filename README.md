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
- **Caching**: Redis with django-redis
- **Rate Limiting**: DRF throttling with Redis backend
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

### PasswordHistory Model

Tracks password history for reuse prevention:

- **Relationship**: ForeignKey to CustomUser
- **Security Data**: password (hashed), changed_at
- **Functionality**: Prevents reuse of last 10 passwords
- **Auto-cleanup**: Maintains only 10 most recent passwords per user

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

### Password Management
- `POST /api/user/password_change_with_old_password` - Change password with old password verification
  - Accepts: old_password, new_password
  - Validation: Old password verification, password history check (prevents reuse of last 10 passwords)
  - Security: Minimum 5 character requirement
  - Returns: Success/error message

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

- **Access Token Lifetime**: 5 minutes (configurable)
- **Refresh Token Lifetime**: 7 days (configurable)
- **Token Rotation**: Enabled for enhanced security
- **Blacklisting**: Tokens are blacklisted after rotation

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

### Caching & Performance

**Redis Configuration:**
- Backend: django_redis.cache.RedisCache
- Connection: Configurable Redis instance
- Client: DefaultClient for optimal performance

**API Rate Limiting:**
- Anonymous users: 100 requests/day
- Authenticated users: 1000 requests/day
- Backend: Redis-based throttling
- Classes: AnonRateThrottle, UserRateThrottle

**Features:**
- Redis-backed caching for improved performance
- Rate limiting to prevent API abuse
- Separate limits for anonymous (100/day) and authenticated users (1000/day)
- Cache-based throttling with automatic cleanup

## Project Setup

### 1. Clone the Repository

```bash
git clone <your-repository-url>
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
  -e POSTGRES_DB=<your_db_name> \
  -e POSTGRES_USER=<your_db_user> \
  -e POSTGRES_PASSWORD=<your_secure_password> \
  -p 5432:5432 \
  -d postgres:15
```

Option 2: Using docker-compose (for testing database):
```bash
cd docker/postgres
docker-compose up -d
```

### 4. Install and Run Redis

**Option 1: Using Docker:**
```bash
docker run --name auth_redis -p 6379:6379 -d redis:7-alpine
```

**Option 2: Local Installation:**
- Windows: Download from https://redis.io/download
- macOS: `brew install redis && brew services start redis`
- Linux: `sudo apt-get install redis-server`

### 5. Create `.env` File

```ini
# .env
DEBUG=False  # Set to True only for development
SECRET_KEY=<your-secure-secret-key>
DATABASE_URL=postgres://<user>:<password>@<host>:<port>/<database>

EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=<your-smtp-host>
EMAIL_PORT=<smtp-port>
EMAIL_USE_TLS=True
EMAIL_HOST_USER=<your-email>
EMAIL_HOST_PASSWORD=<your-email-password>
DEFAULT_FROM_EMAIL=<your-from-email>

# For testing
TEST_DB_NAME=<test_database>
TEST_DB_USER=<test_user>
TEST_DB_PASSWORD=<test_password>
TEST_DB_HOST=localhost
TEST_DB_PORT=5432
```

### 6. Wait for Database and Apply Migrations

```bash
poetry shell
python manage.py wait_for_db  # Custom command to ensure database is ready
python manage.py migrate
```

### 7. Create Superuser (Optional)

```bash
python manage.py createsuperuser
```

### 8. Run Development Server

```bash
python manage.py runserver
```

### 9. Access API Documentation

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

- **Model Tests**: Tests for CustomUser, EmailOTP, and PasswordHistory models
- **API Tests**: Tests for all API endpoints including authentication, user management, email verification, and password change
- **Security Tests**: Password reuse prevention, history tracking, and validation tests
- **Edge Case Tests**: Special characters, unicode, long passwords, and HTTP method restrictions
- **Throttling Tests**: Rate limiting for anonymous and authenticated users
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
- ✅ Password change with old password verification
- ✅ Password history tracking and reuse prevention
- ✅ Redis caching for improved performance
- ✅ API rate limiting and throttling
- ✅ API documentation with Swagger
- ✅ Comprehensive test suite with edge cases

### Security Enhancements Implemented
- ✅ Password reuse prevention (last 10 passwords)
- ✅ Automatic password history management
- ✅ Secure password validation and hashing
- ✅ Rate limiting for OTP requests
- ✅ API throttling (100/day anonymous, 1000/day authenticated)
- ✅ Redis-backed caching and rate limiting
- ✅ Token blacklisting and rotation

### Test Coverage
- ✅ Authentication flow tests
- ✅ User management tests
- ✅ Email verification tests
- ✅ Password change comprehensive test suite
- ✅ Edge case and validation tests
- ✅ Security feature tests
- ✅ Throttling and rate limiting tests

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

