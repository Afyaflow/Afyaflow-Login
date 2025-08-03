#!/usr/bin/env python3
"""
Debug script for JWT authentication issues.
This script helps debug JWT token validation problems.
"""

import os
import sys
import django
import logging

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'afyaflow_auth.settings')
django.setup()

from users.authentication import JWTAuthentication
from django.conf import settings
import jwt

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def debug_jwt_secrets():
    """Debug JWT secrets configuration."""
    print("JWT Secrets Configuration:")
    print("=" * 50)
    
    secrets = {
        'PROVIDER_AUTH_TOKEN_SECRET': getattr(settings, 'PROVIDER_AUTH_TOKEN_SECRET', None),
        'PATIENT_AUTH_TOKEN_SECRET': getattr(settings, 'PATIENT_AUTH_TOKEN_SECRET', None),
        'OPERATIONS_AUTH_TOKEN_SECRET': getattr(settings, 'OPERATIONS_AUTH_TOKEN_SECRET', None),
        'ORG_CONTEXT_TOKEN_SECRET': getattr(settings, 'ORG_CONTEXT_TOKEN_SECRET', None),
        'JWT_SECRET_KEY': getattr(settings, 'JWT_SECRET_KEY', None),
    }
    
    for name, secret in secrets.items():
        if secret:
            preview = secret[:10] + "..." if len(secret) > 10 else secret
            print(f"{name}: {preview} (length: {len(secret)})")
        else:
            print(f"{name}: None")
    
    print()

def debug_token_decode(token):
    """Debug token decoding with different secrets."""
    print("Token Decoding Debug:")
    print("=" * 50)
    
    # First, decode without verification to see payload
    try:
        payload = jwt.decode(token, options={'verify_signature': False})
        print("Token payload (unverified):")
        for key, value in payload.items():
            print(f"  {key}: {value}")
        print()
    except Exception as e:
        print(f"Failed to decode token payload: {e}")
        return
    
    # Try with each secret
    secrets_to_try = [
        ('PROVIDER_AUTH_TOKEN_SECRET', getattr(settings, 'PROVIDER_AUTH_TOKEN_SECRET', None)),
        ('PATIENT_AUTH_TOKEN_SECRET', getattr(settings, 'PATIENT_AUTH_TOKEN_SECRET', None)),
        ('OPERATIONS_AUTH_TOKEN_SECRET', getattr(settings, 'OPERATIONS_AUTH_TOKEN_SECRET', None)),
        ('ORG_CONTEXT_TOKEN_SECRET', getattr(settings, 'ORG_CONTEXT_TOKEN_SECRET', None)),
        ('JWT_SECRET_KEY', getattr(settings, 'JWT_SECRET_KEY', None)),
    ]
    
    print("Attempting to decode with each secret:")
    for secret_name, secret in secrets_to_try:
        if not secret:
            print(f"  {secret_name}: SKIPPED (secret is None)")
            continue
            
        try:
            decoded_payload = jwt.decode(
                token,
                secret,
                algorithms=[settings.JWT_ALGORITHM]
            )
            print(f"  {secret_name}: ✅ SUCCESS")
            print(f"    Decoded payload: {decoded_payload}")
        except jwt.ExpiredSignatureError:
            print(f"  {secret_name}: ❌ EXPIRED")
        except jwt.InvalidSignatureError:
            print(f"  {secret_name}: ❌ INVALID SIGNATURE")
        except Exception as e:
            print(f"  {secret_name}: ❌ ERROR - {str(e)}")
    
    print()

def test_jwt_authentication(token):
    """Test JWT authentication with the actual authentication class."""
    print("JWT Authentication Test:")
    print("=" * 50)
    
    # Create a mock request object
    class MockRequest:
        def __init__(self, token):
            self.headers = {'Authorization': f'Bearer {token}'}
            self.META = {}
    
    request = MockRequest(token)
    authenticator = JWTAuthentication()
    
    try:
        result = authenticator.authenticate(request)
        if result:
            user, payload = result
            print(f"✅ Authentication successful!")
            print(f"User: {user.email}")
            print(f"User Type: {user.user_type}")
            print(f"User Active: {user.is_active}")
            print(f"User Suspended: {user.is_suspended}")
            print(f"Token Payload: {payload}")
        else:
            print("❌ Authentication returned None")
    except Exception as e:
        print(f"❌ Authentication failed: {str(e)}")
    
    print()

def main():
    """Main debug function."""
    print("JWT Authentication Debug Tool")
    print("=" * 60)
    print()
    
    # Debug secrets
    debug_jwt_secrets()
    
    # Get token from user
    print("Please paste your JWT token:")
    token = input().strip()
    
    if not token:
        print("No token provided. Exiting.")
        return
    
    print()
    
    # Debug token structure
    parts = token.split('.')
    print(f"Token structure: {len(parts)} parts (expected: 3)")
    if len(parts) != 3:
        print("❌ Invalid token structure!")
        return
    
    print()
    
    # Debug token decoding
    debug_token_decode(token)
    
    # Test authentication
    test_jwt_authentication(token)
    
    print("Debug complete!")

if __name__ == '__main__':
    main()
