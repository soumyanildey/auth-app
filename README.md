
````markdown
# Auth_App

Auth_App is a Django-based authentication system. It includes user registration, login, role-based access, email OTP verification, password reset, and secure authentication using JWT.

## Features Implemented

- JWT-based authentication using Django REST Framework
- Role-based access control (RBAC)
- Email verification via OTP
- Secure password change (via OTP or current password)
- PostgreSQL as the database backend
- Poetry as the dependency and environment manager
- `.gitignore` respected for environment files and virtual envs
- Local Docker PostgreSQL container setup for development and testing

---
````
## Project Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/Auth_App.git
cd Auth_App
```

---

### 2. Install Dependencies using Poetry

```bash
poetry install
```

---

### 3. Run PostgreSQL Locally via Docker

```bash
docker run --name auth_pg \
  -e POSTGRES_DB=auth_db \
  -e POSTGRES_USER=auth_user \
  -e POSTGRES_PASSWORD=auth_pass \
  -p 5432:5432 \
  -d postgres:15
```

---

### 4. Create `.env` File

```ini
# .env
DEBUG=True
SECRET_KEY=your-django-secret-key
DATABASE_URL=postgres://auth_user:auth_pass@localhost:5432/auth_db

EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your@email.com
EMAIL_HOST_PASSWORD=email-password
```

---

### 5. Apply Migrations & Run Server

```bash
poetry shell
python manage.py migrate
python manage.py runserver
```

---


