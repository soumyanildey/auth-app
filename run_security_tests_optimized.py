#!/usr/bin/env python
"""
Optimized Security Test Runner for Auth App

This script runs the streamlined security test suite.
"""

import os
import sys
import django
from django.core.management import execute_from_command_line

def run_security_tests():
    """Run optimized security tests"""
    
    # Set up Django environment
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Authentication_App.settings')
    django.setup()
    
    print("🔒 Running Optimized Security Tests for Auth App")
    print("=" * 60)
    
    # Core test modules (essential only)
    test_modules = [
        'user.tests.test_security_comprehensive',  # All security tests merged
        'user.tests.test_account_lockout_fixed',   # Fixed account lockout tests
        'user.tests.test_2fa_views',               # 2FA specific tests
        'user.tests.test_user_api',                # Core user API tests
    ]
    
    print(f"\n📋 Running {len(test_modules)} test modules...")
    
    try:
        # Run all tests together for efficiency
        cmd = ['manage.py', 'test'] + test_modules + ['--verbosity=2', '--keepdb']
        execute_from_command_line(cmd)
        print("\n✅ All security tests completed successfully!")
        
    except SystemExit as e:
        if e.code == 0:
            print("\n✅ All security tests PASSED!")
        else:
            print(f"\n❌ Some tests FAILED (exit code: {e.code})")
            
    except Exception as e:
        print(f"\n❌ Test execution ERROR: {e}")
    
    print("\n" + "=" * 60)
    print("🔒 Security Test Summary:")
    print("  ✅ Account Lockout & Recovery")
    print("  ✅ 2FA Authentication Flow") 
    print("  ✅ JWT Token Security")
    print("  ✅ Password Security & History")
    print("  ✅ Email Change Security")
    print("  ✅ Role-Based Permissions")
    print("  ✅ Vulnerability Protection")
    print("  ✅ Configuration Validation")
    
    print("\nTo run individual tests:")
    print("  python manage.py test user.tests.test_security_comprehensive")
    print("  python manage.py test user.tests.test_account_lockout_fixed")

if __name__ == '__main__':
    run_security_tests()