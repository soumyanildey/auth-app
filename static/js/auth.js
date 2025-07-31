// Modern JavaScript for authentication frontend
const API_BASE = `${window.location.origin}/api/user`;

// Load navbar.html into every page
fetch('navbar.html')
  .then(res => {
    if (!res.ok) throw new Error('Navbar not found');
    return res.text();
  })
  .then(html => {
    const placeholder = document.getElementById('navbar-placeholder');
    if (placeholder) {
      placeholder.innerHTML = html;
    }
  })
  .catch(err => {
    console.warn('Optional navbar skipped:', err.message);
  });




// Check server connectivity
const checkServerConnection = async () => {
    try {
        const response = await fetch(`${window.location.origin}/admin/`, {
            method: 'GET',
            mode: 'cors'
        });
        return response.status < 500; // Accept redirects and auth errors as "server running"
    } catch (error) {
        return false;
    }
};

// Get CSRF token from Django
const getCSRFToken = async () => {
    try {
        // First try to get from cookie directly
        const cookies = document.cookie.split(';');
        for (let cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'csrftoken') {
                console.log('CSRF token found in existing cookies');
                return value;
            }
        }

        // If not found, fetch new token from Django admin page
        const response = await fetch(`${window.location.origin}/admin/`, {
            method: 'GET',
            credentials: 'include',
            mode: 'cors',
            cache: 'no-cache'
        });

        // After fetch, check cookies again
        const newCookies = document.cookie.split(';');
        for (let cookie of newCookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'csrftoken') {
                console.log('New CSRF token obtained');
                return value;
            }
        }

        console.log('No CSRF token found');
        return null;
    } catch (error) {
        console.error('CSRF fetch failed:', error);
        return null;
    }
};

// Utility functions
const showMessage = (text, type = 'info') => {
    const messageEl = document.getElementById('message');
    if (!messageEl) {
        // Create message element if it doesn't exist
        const newMessageEl = document.createElement('div');
        newMessageEl.id = 'message';
        document.body.insertBefore(newMessageEl, document.body.firstChild);
        // Now use the newly created element
        newMessageEl.textContent = text;
        newMessageEl.className = `message ${type}`;
        newMessageEl.classList.remove('hidden');
        setTimeout(() => newMessageEl.classList.add('hidden'), 5000);
    } else {
        messageEl.textContent = text;
        messageEl.className = `message ${type}`;
        messageEl.classList.remove('hidden');
        setTimeout(() => messageEl.classList.add('hidden'), 5000);
    }
};

const showLoader = (btnId, show = true) => {
    const btn = document.getElementById(btnId);
    const text = btn.querySelector('.btn-text');
    const loader = btn.querySelector('.btn-loader');

    if (show) {
        text.classList.add('hidden');
        loader.classList.remove('hidden');
        btn.disabled = true;
    } else {
        text.classList.remove('hidden');
        loader.classList.add('hidden');
        btn.disabled = false;
    }
};

const refreshToken = async () => {
    const refresh = localStorage.getItem('refresh_token');
    if (!refresh) return false;

    try {
        const response = await fetch(`${API_BASE}/token/refresh/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh })
        });

        if (response.ok) {
            const data = await response.json();

            // Store new tokens
            if (data.access) localStorage.setItem('access_token', data.access);
            if (data.refresh) localStorage.setItem('refresh_token', data.refresh);

            // ✅ Reschedule next refresh
            scheduleTokenRefresh(data.access);

            return true;
        } else {
            console.warn('Refresh token invalid or expired. Status:', response.status);
        }
    } catch (error) {
        console.error('Token refresh failed:', error);
    }

    // ❌ Clear session and redirect to login
    localStorage.clear();
    alert('Session expired. Please log in again.');
    window.location.href = 'login.html';
    return false;
};

const decodeJWT = (token) => {
    try {
        const base64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
        return JSON.parse(atob(base64));
    } catch (err) {
        console.error('Invalid token:', err);
        return null;
    }
};

const scheduleTokenRefresh = (accessToken = null) => {
    const token = accessToken || localStorage.getItem('access_token');
    if (!token) return;

    const payload = decodeJWT(token);
    if (!payload?.exp) return;

    const now = Math.floor(Date.now() / 1000);
    const expiresIn = payload.exp - now;
    const buffer = 30; // refresh 30 seconds before expiry
    const refreshTime = Math.max((expiresIn - buffer), 0) * 1000;

    console.log(`Next token refresh scheduled in ${refreshTime / 1000} seconds.`);

    setTimeout(() => {
        refreshToken(); // will call this and schedule again
    }, refreshTime);
};


window.addEventListener('load', () => {
    const access = localStorage.getItem('access_token');
    if (access) {
        scheduleTokenRefresh(access);
    }
});



const apiCall = async (endpoint, data = null, method = 'POST') => {
    console.log(`API Call: ${method} ${API_BASE}${endpoint}`);
    let token = localStorage.getItem('access_token');

    const makeRequest = async () => {
        // Get CSRF token first
        const csrfToken = await getCSRFToken();
        if (!csrfToken) {
            console.error('Failed to obtain CSRF token');
        }

        const config = {
            method,
            headers: {
                'Content-Type': 'application/json',
                ...(token && { 'Authorization': `Bearer ${token}` }),
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRFToken': csrfToken  // Always include CSRF token
            },
            credentials: 'include',
            mode: 'cors',
            cache: 'no-cache'
        };

        // Add CSRF token for POST requests
        if (method === 'POST' || method === 'PUT' || method === 'DELETE') {
            const csrfToken = await getCSRFToken();
            if (csrfToken) {
                config.headers['X-CSRFToken'] = csrfToken;
            }
        }

        if (data) config.body = JSON.stringify(data);

        return await fetch(`${API_BASE}${endpoint}`, config);
    };

    let response = await makeRequest();

    // If 401 (unauthorized), try to refresh token
    if (response.status === 401 && await refreshToken()) {
        token = localStorage.getItem('access_token');
        response = await makeRequest();
    }

    console.log('Response status:', response.status);

    let responseData;
    try {
        responseData = await response.json();
    } catch (e) {
        responseData = {};
    }

    return { data: responseData, status: response.status };
};

// Login functionality
if (document.getElementById('loginForm')) {
    const loginForm = document.getElementById('loginForm');
    const otpGroup = document.getElementById('otpGroup');
    let requires2FA = false;

    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        showLoader('loginBtn');

        const formData = new FormData(loginForm);
        const data = Object.fromEntries(formData);

        // Simple server check
        const serverOnline = await checkServerConnection();
        if (!serverOnline) {
            showMessage('Server not available', 'error');
            showLoader('loginBtn', false);
            return;
        }

        try {
            const { data: result, status } = await apiCall('/token/', data);

            if (status === 200) {
                if (result.requires_2fa) {
                    requires2FA = true;
                    otpGroup.classList.remove('hidden');
                    showMessage('Please enter your 2FA code', 'info');
                } else if (result.requires_email_verification) {
                    localStorage.setItem('temp_email', data.email);
                    showMessage('Please verify your email first', 'info');
                    setTimeout(() => window.location.href = 'email-verify.html', 1000);
                } else {
                    localStorage.setItem('access_token', result.access);
                    localStorage.setItem('refresh_token', result.refresh);
                    showMessage('Login successful! 🎉', 'success');
                    setTimeout(() => window.location.href = 'dashboard.html', 1000);
                }
            }
            else if (status === 423) {
        // Account locked case
        showMessage(result.error || 'Your account is locked.', 'error');

    } else {
        // Other errors (e.g., wrong password, bad credentials)
        showMessage(result.detail || 'Login failed.', 'error');
    }
        } catch (error) {
            console.log('Login error:', error);
            showMessage('Authentication failed. Check server logs.', 'error');
        }

        showLoader('loginBtn', false);
    });
}

// Register functionality
if (document.getElementById('registerForm')) {
    const registerForm = document.getElementById('registerForm');
    const passwordInput = document.getElementById('password');
    const strengthIndicator = document.getElementById('passwordStrength');

    // Password strength checker
    passwordInput.addEventListener('input', (e) => {
        const password = e.target.value;
        let strength = 0;

        if (password.length >= 8) strength++;
        if (/[A-Z]/.test(password)) strength++;
        if (/[0-9]/.test(password)) strength++;
        if (/[^A-Za-z0-9]/.test(password)) strength++;

        const levels = ['', 'weak', 'medium', 'strong', 'very-strong'];
        strengthIndicator.className = `password-strength ${levels[strength]}`;
    });

    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        showLoader('registerBtn');

        const formData = new FormData(registerForm);
        const data = Object.fromEntries(formData);

        if (data.password !== data.password2) {
            showMessage('Passwords do not match!', 'error');
            showLoader('registerBtn', false);
            return;
        }

        try {
            const { data: result, status } = await apiCall('/create/', data);

            if (status === 201) {
                showMessage('Account created successfully! Please check your email for verification. 📧', 'success');
                setTimeout(() => window.location.href = 'login.html', 2000);
            } else {
                const errors = Object.values(result).flat().join('. ');
                showMessage(errors || 'Registration failed', 'error');
            }
        } catch (error) {
            showMessage('Network error. Please try again.', 'error');
        }

        showLoader('registerBtn', false);
    });
}

// Function definitions first
const showPasswordModal = () => {
    document.getElementById('passwordModal').classList.remove('hidden');
};

const showPasswordResetModal = (event) => {
    event.preventDefault();
    document.getElementById('passwordResetModal').classList.remove('hidden');
};

// Password reset form handler
// Password reset request handler
if (document.getElementById('passwordResetForm')) {
    document.getElementById('passwordResetForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        showLoader('resetBtn');

        const email = document.getElementById('resetEmail').value;

        try {
            const { data: result, status } = await apiCall('/password_reset/', {
                email,
                // Add the frontend URL for the reset page with proper path format
                reset_url: window.location.origin + '/reset-password.html'
            });

            if (status === 200) {
                showMessage('Password reset instructions sent to your email! 📧', 'success');
                closeModal('passwordResetModal');
                document.getElementById('passwordResetForm').reset();
            } else {
                showMessage(result.detail || 'Failed to send reset instructions', 'error');
            }
        } catch (error) {
            console.error('Password reset error:', error);
            showMessage('Error sending reset instructions', 'error');
        }

        showLoader('resetBtn', false);
    });
}

// Password reset confirmation handler
if (document.getElementById('resetConfirmForm')) {
    const passwordInput = document.getElementById('newPassword');
    const strengthIndicator = document.getElementById('passwordStrength');

    // Password strength checker
    passwordInput?.addEventListener('input', (e) => {
        const password = e.target.value;
        let strength = 0;

        if (password.length >= 8) strength++;
        if (/[A-Z]/.test(password)) strength++;
        if (/[0-9]/.test(password)) strength++;
        if (/[^A-Za-z0-9]/.test(password)) strength++;

        const levels = ['', 'weak', 'medium', 'strong', 'very-strong'];
        strengthIndicator.className = `password-strength ${levels[strength]}`;
    });

    document.getElementById('resetConfirmForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        showLoader('resetConfirmBtn');

        const newPassword = document.getElementById('newPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;

        if (newPassword !== confirmPassword) {
            showMessage('Passwords do not match!', 'error');
            showLoader('resetConfirmBtn', false);
            return;
        }

        // Extract token and uid from URL
        let token, uidb64;

        const urlParams = new URLSearchParams(window.location.search);
        token = urlParams.get('token');
        uidb64 = urlParams.get('uid');

        // Fallback: try path if not found
        if ((!token || !uidb64) && window.location.pathname.includes('/reset-password-confirm/')) {
            const pathParts = window.location.pathname.split('/').filter(Boolean);
            uidb64 = pathParts[pathParts.length - 2];
            token = pathParts[pathParts.length - 1];
        }

        // Clean up token and uidb64
        token = token.replace('/', '');
        uidb64 = uidb64.replace('/', '');

        try {
            const { data: result, status } = await apiCall('/password_reset_confirm/', {
    uid: uidb64,
    token: token,
    new_password: newPassword
});


if (status === 400) {
    console.error("Error:", result);
}


            if (status === 200) {
                showMessage('Password reset successful! You can now login. 🔐', 'success');
                setTimeout(() => window.location.href = 'login.html', 2000);
            } else {
                showMessage(result.detail || 'Failed to reset password', 'error');
            }
        } catch (error) {
            console.error('Password reset confirm error:', error);
            showMessage('Error resetting password', 'error');
        }

        showLoader('resetConfirmBtn', false);
    });
}

const showEmailModal = () => {
    document.getElementById('emailModal').classList.remove('hidden');
};

const showAccountModal = async () => {
    try {
        const { data: user, status } = await apiCall('/me/', null, 'GET');
        if (status === 200) {
            const accountStatusHtml = `
                <div class="modal" id="accountModal">
                    <div class="modal-content">
                        <h2>Account Status</h2>
                        <div class="status-grid">
                            <div class="status-item">
                                <strong>Account Status:</strong>
                                <span class="status-active">Active</span>
                            </div>
                            <div class="status-item">
                                <strong>Email Status:</strong>
                                <span class="${user.is_email_verified ? 'status-verified' : 'status-pending'}">
                                    ${user.is_email_verified ? 'Verified' : 'Pending Verification'}
                                </span>
                            </div>
                            <div class="status-item">
                                <strong>2FA Status:</strong>
                                <span class="${user.is_2fa_enabled ? 'status-enabled' : 'status-disabled'}">
                                    ${user.is_2fa_enabled ? 'Enabled' : 'Disabled'}
                                </span>
                            </div>
                            <div class="status-item">
                                <strong>Account Type:</strong>
                                <span>${String(user.role).charAt(0).toUpperCase() + String(user.role).slice(1)}</span>
                            </div>
                            <div class="status-item">
                                <strong>Last Updated:</strong>
                                <span>${user.updated_at ? new Date(user.updated_at).toLocaleDateString() : 'Not available'}</span>
                            </div>
                            <div class="status-item">
                                <strong>Member Since:</strong>
                                <span>${user.created_at ? new Date(user.created_at).toLocaleDateString() : 'Not available'}</span>
                            </div>
                        </div>
                        <button onclick="closeModal('accountModal')" class="close-btn">Close</button>
                    </div>
                </div>`;

            // Remove existing modal if present
            const existingModal = document.getElementById('accountModal');
            if (existingModal) {
                existingModal.remove();
            }

            // Add new modal to body
            document.body.insertAdjacentHTML('beforeend', accountStatusHtml);
            document.getElementById('accountModal').classList.remove('hidden');
        } else {
            showMessage('Failed to load account status', 'error');
        }
    } catch (error) {
        showMessage('Error loading account status', 'error');
        console.error('Account status error:', error);
    }
};

const showUnblockModal = () => {
    document.getElementById('unblockModal').classList.remove('hidden');
};

const showUsersModal = () => {
    document.getElementById('usersModal').classList.remove('hidden');
    loadUsersList();
};

const showStatsModal = () => {
    document.getElementById('statsModal').classList.remove('hidden');
    loadSystemStats();
};

const showDeleteModal = () => {
    document.getElementById('deleteModal').classList.remove('hidden');
};

// Load user info
const loadUserInfo = async () => {
    try {
        const { data: user, status } = await apiCall('/me/', null, 'GET');
        if (status === 200) {
            // Dashboard profile info
            if (document.getElementById('userName')) {
                document.getElementById('userName').textContent = user.fname || 'User';
            }
            if (document.getElementById('fullName')) {
                document.getElementById('fullName').textContent = `${user.fname || ''} ${user.lname || ''}`;
            }
            if (document.getElementById('userEmail')) {
                document.getElementById('userEmail').textContent = user.email || '';
            }
            if (document.getElementById('userPhone')) {
                document.getElementById('userPhone').textContent = user.phone || 'No phone';
            }
            if (document.getElementById('userRole')) {
                document.getElementById('userRole').textContent = `Role: ${String(user.role).charAt(0).toUpperCase() + String(user.role).slice(1) || 'user'}`;
            }
            // Load profile picture
            if (document.getElementById('profilePic') && user.profile_pic) {
                document.getElementById('profilePic').src = user.profile_pic;
            }
            // Security page info
            if (document.getElementById('2faStatus')) {
                document.getElementById('2faStatus').textContent = user.is_2fa_enabled ? 'Enabled ✅' : 'Not enabled';
                document.getElementById('2faBtn').textContent = user.is_2fa_enabled ? 'Disable' : 'Enable';
            }
            return user;
        }
    } catch (error) {
        console.error('Failed to load user info');
    }
};



// Load profile data for display
const loadProfileData = async () => {
    try {
        const { data: user, status } = await apiCall('/me/', null, 'GET');
        if (status === 200) {
            console.log('User data:', user); // Debug log
            // Display fields
            const displayFields = {
                'displayFullName': `${user.fname || ''} ${user.lname || ''}`,
                'displayEmail': user.email || 'Not provided',
                'displayPhone': user.phone || 'Not provided',
                'displayDob': user.dob || 'Not provided',
                'displayGender': user.gender === 'male' ? 'Male' : user.gender === 'female' ? 'Female' : user.gender === 'other' ? 'Other' : 'Not specified',
                'displayAddress': user.address || 'Not provided',
                'displayCity': user.city || 'Not provided',
                'displayState': user.state || 'Not provided',
                'displayCountry': user.country || 'Not provided',
                'displayPostalCode': user.postal_code || 'Not provided',
                'displayRole': String(user.role).charAt(0).toUpperCase() + String(user.role).slice(1) || 'User',
                'displayEmailVerified': user.is_email_verified ? 'Yes' : 'No',
                'display2FA': user.is_2fa_enabled ? 'Enabled' : 'Disabled',
                'displayCreatedAt': user.created_at ? new Date(user.created_at).toLocaleDateString() : 'Not available',
                'displayUpdatedAt': user.updated_at ? new Date(user.updated_at).toLocaleDateString() : 'Not available',
                'displayBio': user.bio || 'No bio provided'
            };

            Object.entries(displayFields).forEach(([elementId, value]) => {
                const element = document.getElementById(elementId);
                if (element) element.textContent = value;
            });
        }
    } catch (error) {
        showMessage('Failed to load profile data', 'error');
    }
};

// Load security data
const loadSecurityData = async () => {
    await loadUserInfo();
};

// Check admin access
const checkAdminAccess = async () => {
    const user = await loadUserInfo();
    if (user && !['admin', 'superadmin'].includes(user.role)) {
        document.getElementById('admin-link').style.display = 'none';
    }
};

// Call the function when the page loads
document.addEventListener('DOMContentLoaded', checkAdminAccess);

// Dashboard functionality
if (window.location.pathname.includes('dashboard.html')) {
    loadUserInfo();
}

// Profile functionality
if (window.location.pathname.includes('profile.html')) {
    loadProfileData();
}

// Security functionality
if (window.location.pathname.includes('security.html')) {
    loadSecurityData();
}

// Admin functionality
if (window.location.pathname.includes('admin.html')) {
    checkAdminAccess();
}

// 2FA functionality
const toggle2FA = async () => {
    const btn = document.getElementById('2faBtn');
    const isEnabled = btn.textContent === 'Disable';

    if (isEnabled) {
        showMessage('2FA disable functionality not implemented yet', 'info');
        return;
    }

    try {
        const { data: result, status } = await apiCall('/enable_2fa', {});
        if (status === 200) {
            document.getElementById('qrImage').src = `data:image/png;base64,${result.qr_code}`;
            document.getElementById('qrCode').classList.remove('hidden');
            document.getElementById('2faModal').classList.remove('hidden');
        }
    } catch (error) {
        showMessage('Failed to enable 2FA', 'error');
    }
};

const verify2FA = async () => {
    const otp = document.getElementById('verifyOtp').value;
    if (!otp || otp.length !== 6) {
        showMessage('Please enter a valid 6-digit code', 'error');
        return;
    }

    try {
        const { data: result, status } = await apiCall('/verify_2fa', { otp });
        if (status === 200) {
            showMessage('2FA enabled successfully! 🔐', 'success');
            closeModal('2faModal');
            document.getElementById('2faStatus').textContent = 'Enabled ✅';
            document.getElementById('2faBtn').textContent = 'Disable';
        } else {
            showMessage(result.error || 'Verification failed', 'error');
        }
    } catch (error) {
        showMessage('Verification failed', 'error');
    }
};

// Modal functions
const showSecurityModal = () => {
    document.getElementById('securityModal').classList.remove('hidden');
};

const showProfileModal = () => {
    window.location.href = 'profile.html';
};

const showProfileEditModal = () => {
    loadProfileEditData();
    document.getElementById('profileEditModal').classList.remove('hidden');
};

const loadProfileEditData = async () => {
    try {
        const { data: user, status } = await apiCall('/me/', null, 'GET');
        if (status === 200) {
            const fields = {
                'editFname': 'fname',
                'editLname': 'lname',
                'editPhone': 'phone',
                'editDob': 'dob',
                'editGender': 'gender',
                'editBio': 'bio',
                'editAddress': 'address',
                'editCity': 'city',
                'editState': 'state',
                'editCountry': 'country',
                'editPostalCode': 'postal_code'
            };

            Object.entries(fields).forEach(([elementId, userField]) => {
                const element = document.getElementById(elementId);
                if (element) element.value = user[userField] || '';
            });
        }
    } catch (error) {
        showMessage('Failed to load profile data', 'error');
    }
};

const closeModal = (modalId) => {
    document.getElementById(modalId).classList.add('hidden');
};

// Logout function
const logout = async () => {
    const refreshToken = localStorage.getItem('refresh_token');
    if (refreshToken) {
        try {
            await apiCall('/logout/', { refresh: refreshToken });
        } catch (error) {
            console.error('Logout API call failed');
        }
    }

    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    showMessage('Logged out successfully! 👋', 'success');
    setTimeout(() => window.location.href = 'login.html', 1000);
};

// Check authentication on protected pages
const checkAuth = () => {
    const token = localStorage.getItem('access_token');
    const currentPage = window.location.pathname.split('/').pop();

    if (currentPage === 'dashboard.html' && !token) {
        window.location.href = 'login.html';
    }
};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    checkAuth();

    // Close modals when clicking outside
    document.addEventListener('click', (e) => {
        if (e.target.classList.contains('modal')) {
            e.target.classList.add('hidden');
        }
    });
});

// Cancel 2FA setup
const cancel2FASetup = async () => {
    try {
        await apiCall('/cancel_2fa_setup', {});
        showMessage('2FA setup cancelled', 'info');
        closeModal('2faModal');
    } catch (error) {
        showMessage('Failed to cancel 2FA setup', 'error');
    }
};

// Profile edit form handler
if (document.getElementById('profileEditForm')) {
    document.getElementById('profileEditForm').addEventListener('submit', async (e) => {
        e.preventDefault();

        const formData = new FormData(e.target);

        try {
            const token = localStorage.getItem('access_token');
            const csrfToken = await getCSRFToken();

            const response = await fetch(`${API_BASE}/me/`, {
                method: 'PATCH',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    ...(csrfToken && { 'X-CSRFToken': csrfToken })
                },
                credentials: 'include',
                body: formData
            });

            if (response.ok) {
                showMessage('Profile updated successfully! ✅', 'success');
                closeModal('profileEditModal');
                // Reload dashboard data
                if (window.location.pathname.includes('dashboard.html')) {
                    loadUserInfo();
                }
                // Reload profile data
                if (window.location.pathname.includes('profile.html')) {
                    loadProfileData();
                }
            } else {
                const result = await response.json();
                const errorMsg = result.detail || Object.values(result).flat().join(', ') || 'Failed to update profile';
                showMessage(errorMsg, 'error');
            }
        } catch (error) {
            showMessage('Failed to update profile', 'error');
        }
    });
}

const updateProfile = async (data) => {
    try {
        console.log('Sending data:', data);
        const { data: result, status } = await apiCall('/me/', data, 'PUT');
        console.log('Response:', result, status);
        if (status === 200) {
            showMessage('Profile updated successfully! ✅', 'success');
            closeModal('profileEditModal');
            // Reload dashboard data if on dashboard
            if (window.location.pathname.includes('dashboard.html')) {
                loadUserInfo();
            }
            // Reload profile data if on profile page
            if (window.location.pathname.includes('profile.html')) {
                loadProfileData();
            }
        } else {
            console.log('Error details:', result);
            const errorMsg = result.detail || Object.values(result).flat().join(', ') || 'Failed to update profile';
            showMessage(errorMsg, 'error');
        }
    } catch (error) {
        console.log('Update error:', error);
        showMessage('Failed to update profile', 'error');
    }
};

// Password change handler
if (document.getElementById('passwordForm')) {
    document.getElementById('passwordForm').addEventListener('submit', async (e) => {
        e.preventDefault();

        const formData = new FormData(e.target);
        const data = Object.fromEntries(formData);

        try {
            const { status } = await apiCall('/password_change_with_old_password', data);
            if (status === 200) {
                showMessage('Password changed successfully! 🔑', 'success');
                closeModal('passwordModal');
                e.target.reset();
            } else {
                showMessage('Failed to change password', 'error');
            }
        } catch (error) {
            showMessage('Failed to change password', 'error');
        }
    });
}

// Email change handler
if (document.getElementById('emailForm')) {
    document.getElementById('emailForm').addEventListener('submit', async (e) => {
        e.preventDefault();

        const formData = new FormData(e.target);
        const data = Object.fromEntries(formData);

        try {
            const { status } = await apiCall('/request-email-otp/', data);
            if (status === 200) {
                document.getElementById('hiddenNewEmail').value = data.new_email;
                closeModal('emailModal');
                document.getElementById('emailOtpModal').classList.remove('hidden');
                showMessage('OTP sent to new email! 📧', 'info');
            } else {
                showMessage('Failed to send OTP', 'error');
            }
        } catch (error) {
            showMessage('Failed to send OTP', 'error');
        }
    });
}

// Email OTP verification handler
if (document.getElementById('emailOtpForm')) {
    document.getElementById('emailOtpForm').addEventListener('submit', async (e) => {
        e.preventDefault();

        const formData = new FormData(e.target);
        const data = Object.fromEntries(formData);

        try {
            const { status } = await apiCall('/verify-email-otp/', data);
            if (status === 200) {
                showMessage('Email updated successfully! ✅', 'success');
                closeModal('emailOtpModal');
                e.target.reset();
            } else {
                showMessage('Invalid OTP', 'error');
            }
        } catch (error) {
            showMessage('Failed to verify OTP', 'error');
        }
    });
}

// Unblock user handler
if (document.getElementById('unblockForm')) {
    document.getElementById('unblockForm').addEventListener('submit', async (e) => {
        e.preventDefault();

        const formData = new FormData(e.target);
        const data = Object.fromEntries(formData);

        try {
            const { status } = await apiCall('/unblock_user', data);
            if (status === 200) {
                showMessage('User unblocked successfully! 🔓', 'success');
                closeModal('unblockModal');
                e.target.reset();
            } else {
                showMessage('Failed to unblock user', 'error');
            }
        } catch (error) {
            showMessage('Failed to unblock user', 'error');
        }
    });
}

// Load users list
const loadUsersList = async () => {
    try {
        const { data: users, status } = await apiCall('/admin/', null, 'GET');
        if (status === 200) {
            const usersList = document.getElementById('usersList');
            usersList.innerHTML = users.map(user => `
                <div style="padding: 10px; border: 1px solid #ddd; margin: 5px 0; border-radius: 5px;">
                    <strong>${user.fname} ${user.lname}</strong><br>
                    <small>${user.email} | Role: ${user.role} | 2FA: ${user.is_2fa_enabled ? 'Yes' : 'No'}</small>
                </div>
            `).join('');
        }
    } catch (error) {
        document.getElementById('usersList').innerHTML = '<p>Failed to load users</p>';
    }
};

// Load system stats
const loadSystemStats = () => {
    document.getElementById('totalUsers').textContent = '150';
    document.getElementById('activeUsers').textContent = '142';
    document.getElementById('blockedUsers').textContent = '8';
    document.getElementById('twoFAUsers').textContent = '89';
};

// Test throttling
const testThrottling = async () => {
    try {
        const { status } = await apiCall('/private_test-throttle', null, 'GET');
        if (status === 200) {
            showMessage('Throttling test passed! ✅', 'success');
        } else {
            showMessage('Throttling limit reached', 'error');
        }
    } catch (error) {
        showMessage('Throttling test failed', 'error');
    }
};

// Delete account handler
if (document.getElementById('deleteForm')) {
    document.getElementById('deleteForm').addEventListener('submit', async (e) => {
        e.preventDefault();

        const password = document.getElementById('deletePassword').value;
        if (!confirm('Are you absolutely sure? This cannot be undone!')) {
            return;
        }

        try {
            const { status } = await apiCall('/delete/', null, 'DELETE');
            if (status === 204) {
                showMessage('Account deleted successfully', 'success');
                localStorage.clear();
                setTimeout(() => window.location.href = 'index.html', 2000);
            } else {
                showMessage('Failed to delete account', 'error');
            }
        } catch (error) {
            showMessage('Failed to delete account', 'error');
        }
    });
}

// Add smooth animations
document.addEventListener('DOMContentLoaded', () => {
    // Animate cards on load
    const cards = document.querySelectorAll('.auth-card, .dashboard-card, .welcome-card');
    cards.forEach((card, index) => {
        card.style.animationDelay = `${index * 0.1}s`;
    });

    // Add navigation highlighting
    const currentPage = window.location.pathname.split('/').pop();
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPage) {
            link.style.background = 'var(--primary)';
            link.style.color = 'white';
        }
    });
});




// --- Phone Masking ---
const maskPhone = (phone) => {
  if (!phone || phone.length < 4) return "Not set";
  return "******" + phone.slice(-4);
};

// --- Populate masked phone each time modal is opened ---
document.querySelectorAll('button[onclick*="smsModal"]').forEach(btn => {
  btn.addEventListener('click', async () => {
    // Get user profile to fetch phone
    const { data: user, status } = await apiCall('/me/', null, 'GET');
    const maskedPhone = (status === 200 && user.phone) ? maskPhone(user.phone) : "Not added";
    document.getElementById('maskedPhone').textContent = maskedPhone;
  });
});

// --- SMS 2FA Flow ---
const smsForm = document.getElementById('smsSetupForm');
if (smsForm) {
  const sendBtn   = document.getElementById('sendSmsOtpBtn');
  const verifyBtn = document.getElementById('verifySmsOtpBtn');
  const smsStatus = document.getElementById('smsStatus');

  sendBtn.addEventListener('click', async () => {
    smsStatus.textContent = '';
    sendBtn.disabled = true;
    sendBtn.querySelector('.btn-text').classList.add('hidden');
    sendBtn.querySelector('.btn-loader').classList.remove('hidden');
    // Use correct backend endpoint!
    const { data, status } = await apiCall('/request-sms-otp/', {});
    sendBtn.disabled = false;
    sendBtn.querySelector('.btn-text').classList.remove('hidden');
    sendBtn.querySelector('.btn-loader').classList.add('hidden');
    if (status === 200) {
      smsStatus.textContent = "OTP sent to your registered phone!";
      smsStatus.className = "success";
    } else {
      smsStatus.textContent = data.detail || "Failed to send OTP.";
      smsStatus.className = "error";
    }
  });

  smsForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    smsStatus.textContent = '';
    verifyBtn.disabled = true;
    verifyBtn.querySelector('.btn-text').classList.add('hidden');
    verifyBtn.querySelector('.btn-loader').classList.remove('hidden');
    const otp = document.getElementById('smsOtp').value;
    // Use correct backend endpoint!
    const { data, status } = await apiCall('/verify-sms-otp/', { otp });
    verifyBtn.disabled = false;
    verifyBtn.querySelector('.btn-text').classList.remove('hidden');
    verifyBtn.querySelector('.btn-loader').classList.add('hidden');
    if (status === 200) {
      smsStatus.textContent = "SMS 2FA is now enabled.";
      smsStatus.className = "success";
      setTimeout(() => {
        closeModal('smsModal');
        smsForm.reset();
        smsStatus.textContent = '';
      }, 1900);
    } else {
      smsStatus.textContent = data.detail || "Invalid OTP";
      smsStatus.className = "error";
    }
  });
}


function showModal(id) {
  document.getElementById(id).classList.remove('hidden');
}


document.getElementById('resendSmsOtpLink')?.addEventListener('click', async (e) => {
  e.preventDefault();
  const sendBtn   = document.getElementById('sendSmsOtpBtn');
  const smsStatus = document.getElementById('smsStatus');
  smsStatus.textContent = '';
  sendBtn.disabled = true;
  const { data, status } = await apiCall('/request-sms-otp/', {});
  sendBtn.disabled = false;
  if (status === 200) {
    smsStatus.textContent = "OTP resent!";
    smsStatus.className = "success";
  } else {
    smsStatus.textContent = data.detail || "Failed to resend OTP.";
    smsStatus.className = "error";
  }
});

