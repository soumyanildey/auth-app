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
                const errorMsg = result?.error || result?.detail || 'Failed to reset password';
                if (errorMsg.includes('recent')) {
                    showMessage('⚠️ Cannot reuse recent passwords. Please choose a different password.', 'error');
                } else {
                    showMessage(errorMsg, 'error');
                }
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
            const { data: result, status } = await apiCall('/password_change_with_old_password', data);
            if (status === 200) {
                showModalMessage('passwordModalMessage', 'Password changed successfully! 🔑', 'success');
                setTimeout(() => {
                    closeModal('passwordModal');
                    e.target.reset();
                }, 1500);
            } else {
                const errorMsg = result?.error || result?.detail || 'Failed to change password';
                if (errorMsg.includes('recent ones')) {
                    showModalMessage('passwordModalMessage', '⚠️ Cannot reuse recent passwords. Please choose a different password that you haven\'t used recently.', 'error');
                } else {
                    showModalMessage('passwordModalMessage', errorMsg, 'error');
                }
            }
        } catch (error) {
            showModalMessage('passwordModalMessage', 'Failed to change password', 'error');
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
        // Get current user info to determine role
        const { data: currentUser } = await apiCall('/me/', null, 'GET');
        const endpoint = currentUser.role === 'superadmin' ? '/superadmin/' : '/admin/';
        const roleText = currentUser.role === 'superadmin' ? 'Super Admin View (Users Only)' : 'Admin View (Users Only)';
        
        document.getElementById('roleIndicator').textContent = roleText;
        
        const { data: users, status } = await apiCall(endpoint, null, 'GET');
        if (status === 200) {
            console.log('Users data:', users); // Debug log
            document.getElementById('usersCount').textContent = `${users.length} users`;
            
            const usersList = document.getElementById('usersList');
            usersList.innerHTML = users.map((user, index) => `
                <div class="user-card">
                    <div class="user-main">
                        <div class="user-info">
                            <div class="user-name">${user.fname} ${user.lname}</div>
                            <div class="user-details">
                                <span>📧 ${user.email}</span>
                                <span class="user-badge role-${user.role}">${user.role.toUpperCase()}</span>
                                <span class="${user.is_active ? 'status-active' : 'status-blocked'}">
                                    ${user.is_active ? '✅ Active' : '🚫 Blocked'}
                                </span>
                                <span>🛡️ 2FA: ${user.is_2fa_enabled ? 'On' : 'Off'}</span>
                                <span>📱 Phone: ${user.phone || 'Not set'}</span>
                            </div>
                        </div>
                        <div class="user-actions">
                            <button class="btn-action delete" onclick="deleteUser('${user.email}')" title="Delete User">🗑️</button>
                        </div>
                    </div>
                </div>
            `).join('');
        }
    } catch (error) {
        document.getElementById('usersList').innerHTML = '<div class="user-card"><p style="color: #d32f2f; text-align: center;">❌ Failed to load users</p></div>';
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
    
    // Initialize Google Auth if on login page
    if (document.getElementById('googleLoginBtn')) {
        initGoogleAuth();
    }
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

// Google OAuth2 Implementation
let googleConfig = null;

// Load Google OAuth configuration with caching
const loadGoogleConfig = async () => {
    if (googleConfig) return googleConfig;
    try {
        const { data, status } = await apiCall('/google-config/', null, 'GET');
        if (status === 200) {
            googleConfig = data;
            return data;
        }
    } catch (error) {
        console.error('Failed to load Google config:', error);
    }
    return null;
};

// Handle Google OAuth login
const handleGoogleLogin = async () => {
    if (!googleConfig) {
        await loadGoogleConfig();
    }
    
    if (!googleConfig || !googleConfig.configured) {
        showMessage('Google OAuth not configured', 'error');
        return;
    }
    
    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
        `client_id=${googleConfig.client_id}&` +
        `redirect_uri=${encodeURIComponent(window.location.href)}&` +
        `response_type=token&` +
        `scope=profile email&` +
        `state=google_login`;
    
    window.location.href = authUrl;
};

// Handle Google OAuth response (for direct redirects)
const handleGoogleResponse = async (response) => {
    if (!response.access_token) {
        showMessage('Google authentication failed', 'error');
        return;
    }
    
    try {
        const { data, status } = await apiCall('/social/google/', {
            access_token: response.access_token
        });
        
        if (status === 200 && data.success) {
            localStorage.setItem('access_token', data.access);
            localStorage.setItem('refresh_token', data.refresh);
            showMessage('Successfully signed in with Google! 🎉', 'success');
            setTimeout(() => window.location.href = 'dashboard.html', 1500);
        } else {
            showMessage(data.message || 'Google authentication failed', 'error');
        }
    } catch (error) {
        console.error('Google login error:', error);
        showMessage('Failed to authenticate with Google', 'error');
    }
};

// Initialize Google Auth
const initGoogleAuth = async () => {
    const config = await loadGoogleConfig();
    if (!config || !config.configured) {
        console.warn('Google OAuth not configured');
        return;
    }
    
    const googleBtn = document.getElementById('googleLoginBtn');
    if (googleBtn) {
        googleBtn.addEventListener('click', handleGoogleLogin);
    }
};

// ===== ACTIVITY LOG FUNCTIONALITY =====

// Show Activity Log Modal
const showActivityLogModal = () => {
    document.getElementById('activityLogModal').classList.remove('hidden');
    document.getElementById('activityResults').classList.add('hidden');
    document.getElementById('activityLogForm').reset();
};

// Activity Log Form Handler
if (document.getElementById('activityLogForm')) {
    document.getElementById('activityLogForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const email = document.getElementById('userEmail').value.trim();
        if (!email) {
            showMessage('Please enter a user email', 'error');
            return;
        }

        try {
            const { data: result, status } = await apiCall('/activity-log/', { email });
            
            if (status === 200) {
                displayActivityLogs(result);
            } else if (status === 404) {
                showMessage('User not found', 'error');
            } else if (status === 403) {
                showMessage('Access denied. Admin privileges required.', 'error');
            } else {
                showMessage(result.error || 'Failed to load activity logs', 'error');
            }
        } catch (error) {
            console.error('Activity log error:', error);
            showMessage('Error loading activity logs', 'error');
        }
    });
}

// Display Activity Logs
const displayActivityLogs = (result) => {
    const userInfo = document.getElementById('userInfo');
    const activityList = document.getElementById('activityList');
    const activityResults = document.getElementById('activityResults');

    // Display user info
    userInfo.innerHTML = `
        <strong>Activity Log for:</strong> ${result.user}
    `;

    // Display activity logs
    if (result.logs && result.logs.length > 0) {
        activityList.innerHTML = result.logs.map((log, index) => `
            <div class="activity-item" onclick="toggleActivityDetails(${index})">
                <div class="activity-main">
                    <div class="activity-action">
                        ${getActionIcon(log.action)} ${log.action}
                        <span class="expand-icon">▼</span>
                    </div>
                    <div class="activity-summary">
                        📍 ${log.location} • 🌐 ${log.ip_address}
                    </div>
                    <div class="activity-details hidden" id="details-${index}">
                        <div class="detail-grid">
                            <div class="detail-item">
                                <strong>🕐 Timestamp:</strong>
                                <span>${new Date(log.timestamp).toLocaleString()}</span>
                            </div>
                            <div class="detail-item">
                                <strong>📍 Location:</strong>
                                <span>${log.location || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <strong>🌐 IP Address:</strong>
                                <span>${log.ip_address || 'Unknown'}</span>
                            </div>
                            <div class="detail-item">
                                <strong>💻 Browser:</strong>
                                <span>${parseBrowser(log.device)}</span>
                            </div>
                            <div class="detail-item">
                                <strong>🖥️ Full User Agent:</strong>
                                <span title="${log.device}">${(log.device || 'Unknown').length > 40 ? (log.device || 'Unknown').substring(0, 40) + '...' : (log.device || 'Unknown')}</span>
                            </div>
                            <div class="detail-item">
                                <strong>🔍 Action Type:</strong>
                                <span>${log.action}</span>
                            </div>
                            <div class="detail-item">
                                <strong>⏰ Time Ago:</strong>
                                <span>${formatActivityTime(log.timestamp)}</span>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="activity-time">
                    ${formatActivityTime(log.timestamp)}
                </div>
            </div>
        `).join('');
    } else {
        activityList.innerHTML = `
            <div class="no-activity">
                <p>No activity logs found for this user.</p>
            </div>
        `;
    }

    // Show results
    activityResults.classList.remove('hidden');
};

// Format activity timestamp
const formatActivityTime = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    
    return date.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
};

// Activity Log Quick Search (Optional Enhancement)
const searchActivityLogs = async (email) => {
    if (!email || email.length < 3) return;
    
    try {
        const { data: result, status } = await apiCall('/activity-log/', { email });
        if (status === 200) {
            return result.logs.length;
        }
    } catch (error) {
        console.error('Quick search error:', error);
    }
    return 0;
};

// Add activity log count to user search (if needed)
const enhanceUserSearch = async () => {
    const emailInput = document.getElementById('userEmail');
    if (emailInput) {
        emailInput.addEventListener('blur', async (e) => {
            const email = e.target.value.trim();
            if (email && email.includes('@')) {
                const count = await searchActivityLogs(email);
                if (count > 0) {
                    emailInput.title = `${count} activity logs found`;
                }
            }
        });
    }
};

// Toggle activity details
const toggleActivityDetails = (index) => {
    const detailsEl = document.getElementById(`details-${index}`);
    const activityItem = detailsEl.closest('.activity-item');
    
    if (detailsEl.classList.contains('hidden')) {
        detailsEl.classList.remove('hidden');
        activityItem.classList.add('expanded');
    } else {
        detailsEl.classList.add('hidden');
        activityItem.classList.remove('expanded');
    }
};

// Get action icon
const getActionIcon = (action) => {
    const icons = {
        'Login': '🔐',
        'Logout': '🚪',
        'Password Change': '🔑',
        'Email Change': '📧',
        'Profile Update': '👤',
        '2FA Enable': '🛡️',
        '2FA Disable': '🔓',
        'Account Block': '🚫',
        'Account Unblock': '✅',
        'OTP Request': '📱',
        'OTP Verify': '✔️'
    };
    return icons[action] || '📋';
};

// Parse browser from user agent
const parseBrowser = (userAgent) => {
    if (!userAgent) return 'Unknown';
    
    if (userAgent.includes('Chrome/')) return userAgent.match(/Chrome\/([\d.]+)/)?.[0] || 'Chrome';
    if (userAgent.includes('Firefox/')) return userAgent.match(/Firefox\/([\d.]+)/)?.[0] || 'Firefox';
    if (userAgent.includes('Safari/') && !userAgent.includes('Chrome')) return 'Safari';
    if (userAgent.includes('Edge/')) return userAgent.match(/Edge\/([\d.]+)/)?.[0] || 'Edge';
    
    return userAgent.length > 50 ? userAgent.substring(0, 50) + '...' : userAgent;
};

// Show message in modal
const showModalMessage = (elementId, text, type = 'info') => {
    const messageEl = document.getElementById(elementId);
    if (messageEl) {
        messageEl.textContent = text;
        messageEl.className = `modal-message ${type}`;
        messageEl.classList.remove('hidden');
        setTimeout(() => messageEl.classList.add('hidden'), 5000);
    }
};

// Initialize activity log enhancements
document.addEventListener('DOMContentLoaded', () => {
    if (window.location.pathname.includes('admin.html')) {
        enhanceUserSearch();
    }
});

// ===== SYSTEM STATS FUNCTIONALITY =====

// Show System Stats Modal
async function showStatsModal() {
    const modal = document.getElementById('statsModal');
    const statsGrid = document.getElementById('systemStats');
    const loading = document.getElementById('statsLoading');
    
    modal.classList.remove('hidden');
    statsGrid.classList.add('hidden');
    loading.classList.remove('hidden');
    
    try {
        const response = await fetch('/api/user/system-stats/', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            updateStatsDisplay(data);
        } else {
            throw new Error('Failed to fetch stats');
        }
    } catch (error) {
        console.error('Error fetching stats:', error);
        showMessage('Failed to load system statistics', 'error');
        // Show default values on error
        updateStatsDisplay({
            total_users: 'N/A',
            active_users: 'N/A',
            blocked_users: 'N/A',
            total_2fa_enabled: 'N/A',
            total_social_accounts: 'N/A',
            total_email_verified: 'N/A',
            total_phone_verified: 'N/A'
        });
    } finally {
        loading.classList.add('hidden');
        statsGrid.classList.remove('hidden');
    }
}

function updateStatsDisplay(data) {
    document.getElementById('totalUsers').textContent = data.total_users || '0';
    document.getElementById('activeUsers').textContent = data.active_users || '0';
    document.getElementById('blockedUsers').textContent = data.blocked_users || '0';
    document.getElementById('twoFAUsers').textContent = data.total_2fa_enabled || '0';
    document.getElementById('failedLogins').textContent = data.total_social_accounts || '0';
    document.getElementById('newSignups').textContent = data.total_email_verified || '0';
    document.getElementById('phoneVerified').textContent = data.total_phone_verified || '0';
}
// ===== MODAL FUNCTIONALITY =====

function closeModal(modalId) {
    document.getElementById(modalId).classList.add('hidden');
}
// User management functions
const editUser = async (userEmail) => {
    showMessage(`Edit functionality for ${userEmail} - Feature coming soon`, 'info');
};

const deleteUser = async (userEmail) => {
    if (!confirm(`Are you sure you want to delete user: ${userEmail}?`)) {
        return;
    }
    showMessage(`Delete functionality for ${userEmail} - Feature coming soon`, 'info');
};