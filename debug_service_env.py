#!/usr/bin/env python
"""
Debug script to check service account environment variables.
"""

import os
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'afyaflow_auth.settings')
django.setup()

def debug_service_env():
    """Debug service account environment variables."""
    
    print("🔍 Debugging Service Account Environment Variables")
    print("=" * 60)
    
    # Check SERVICE_ACCOUNT_IDS
    service_ids_str = os.getenv('SERVICE_ACCOUNT_IDS', '')
    print(f"SERVICE_ACCOUNT_IDS: '{service_ids_str}'")
    
    if service_ids_str:
        service_ids = [sid.strip() for sid in service_ids_str.split(',') if sid.strip()]
        print(f"Parsed service IDs: {service_ids}")
        
        for service_id in service_ids:
            print(f"\n📋 Checking {service_id}:")
            
            # Normalize the service ID
            normalized_id = service_id.upper().replace('-', '_').replace('.', '_')
            print(f"   Normalized ID: {normalized_id}")
            
            # Check for TYPE
            type_var = f'SERVICE_ACCOUNT_{normalized_id}_TYPE'
            type_value = os.getenv(type_var)
            print(f"   {type_var}: '{type_value}'")
            
            # Check for PERMISSIONS
            perm_var = f'SERVICE_ACCOUNT_{normalized_id}_PERMISSIONS'
            perm_value = os.getenv(perm_var, '')
            print(f"   {perm_var}: '{perm_value}'")
            
            # Status
            if type_value:
                print(f"   ✅ Configuration found")
            else:
                print(f"   ❌ Missing TYPE configuration")
    else:
        print("❌ No SERVICE_ACCOUNT_IDS found")
    
    print(f"\n🌍 All Environment Variables containing 'SERVICE_ACCOUNT':")
    service_env_vars = {k: v for k, v in os.environ.items() if 'SERVICE_ACCOUNT' in k}
    
    if service_env_vars:
        for key, value in sorted(service_env_vars.items()):
            print(f"   {key}: '{value}'")
    else:
        print("   No SERVICE_ACCOUNT environment variables found")
    
    print(f"\n🔧 Expected Variable Names:")
    expected_vars = [
        'SERVICE_ACCOUNT_IDS',
        'SERVICE_ACCOUNT_BILLING_SERVICE_TYPE',
        'SERVICE_ACCOUNT_BILLING_SERVICE_PERMISSIONS',
        'SERVICE_ACCOUNT_PATIENTS_SERVICE_TYPE', 
        'SERVICE_ACCOUNT_PATIENTS_SERVICE_PERMISSIONS',
        'SERVICE_ACCOUNT_MEDICAL_RECORDS_SERVICE_TYPE',
        'SERVICE_ACCOUNT_MEDICAL_RECORDS_SERVICE_PERMISSIONS'
    ]
    
    for var in expected_vars:
        value = os.getenv(var)
        status = "✅" if value else "❌"
        print(f"   {status} {var}: '{value}'")

if __name__ == '__main__':
    debug_service_env()
