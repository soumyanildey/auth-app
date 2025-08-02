# Google OAuth2 Setup Guide

## Current Status
✅ Backend Google OAuth endpoints implemented  
✅ Frontend Google OAuth2 implicit flow implemented  
✅ Google OAuth credentials configured in .env  

## Google Cloud Console Setup

1. **Go to Google Cloud Console**: https://console.cloud.google.com/
2. **Create/Select Project**: Create a new project or select existing one
3. **Enable Google+ API**: 
   - Go to "APIs & Services" > "Library"
   - Search for "Google+ API" and enable it
4. **Configure OAuth Consent Screen**:
   - Go to "APIs & Services" > "OAuth consent screen"
   - Choose "External" user type
   - Fill required fields (App name, User support email, Developer contact)
5. **Create OAuth 2.0 Credentials**:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth 2.0 Client IDs"
   - Application type: "Web application"
   - Add authorized redirect URIs:
     - `http://localhost:8000/static/login.html`
     - `http://127.0.0.1:8000/static/login.html`
     - Add your production domain when ready

## Environment Configuration

Add to your `.env` file:
```ini
GOOGLE_OAUTH2_CLIENT_ID=your-google-client-id
GOOGLE_OAUTH2_CLIENT_SECRET=your-google-client-secret
```

## How It Works

1. **User clicks "Continue with Google"** on login page
2. **Popup opens** with Google OAuth consent screen
3. **User authorizes** the application
4. **Google redirects** back to login.html with access token in URL hash
5. **Frontend extracts token** and sends to backend `/social/google/` endpoint
6. **Backend validates token** with Google API and creates/logs in user
7. **User is redirected** to dashboard with JWT tokens

## Testing

1. Start your Django server: `python manage.py runserver`
2. Open `http://localhost:8000/static/login.html`
3. Click "Continue with Google" button
4. Complete Google OAuth flow
5. Should redirect to dashboard upon success

## Troubleshooting

- **"OAuth not configured" error**: Check if GOOGLE_OAUTH2_CLIENT_ID is set in .env
- **"Redirect URI mismatch"**: Add your current URL to authorized redirect URIs in Google Console
- **"Invalid client"**: Verify client ID matches the one in Google Console
- **Popup blocked**: Allow popups for your domain in browser settings