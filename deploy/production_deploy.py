#!/usr/bin/env python
"""
Production deployment script for Afyaflow GraphQL Gateway compliance.
Handles database migrations, service account setup, and system validation.
"""

import os
import sys
import subprocess
import time
import json
from datetime import datetime
from typing import Dict, List, Any, Optional

class ProductionDeployer:
    """
    Production deployment manager for Afyaflow auth service.
    """
    
    def __init__(self, environment: str = 'production'):
        self.environment = environment
        self.deployment_id = f"deploy-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.log_file = f"deployment-{self.deployment_id}.log"
        
    def log(self, message: str, level: str = 'INFO'):
        """Log deployment messages."""
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] [{level}] {message}"
        print(log_entry)
        
        # Write to log file
        with open(self.log_file, 'a') as f:
            f.write(log_entry + '\n')
    
    def run_command(self, command: str, check: bool = True) -> subprocess.CompletedProcess:
        """Run a shell command and log the result."""
        self.log(f"Executing: {command}")
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                check=check
            )
            
            if result.stdout:
                self.log(f"STDOUT: {result.stdout.strip()}")
            if result.stderr:
                self.log(f"STDERR: {result.stderr.strip()}", 'WARNING')
                
            return result
            
        except subprocess.CalledProcessError as e:
            self.log(f"Command failed with exit code {e.returncode}: {e.stderr}", 'ERROR')
            raise
    
    def check_prerequisites(self) -> bool:
        """Check deployment prerequisites."""
        self.log("Checking deployment prerequisites...")
        
        checks = [
            ("Python version", "python --version"),
            ("Django installation", "python -m django --version"),
            ("Database connectivity", "python manage.py check --database default"),
            ("Environment variables", self._check_env_vars),
        ]
        
        for check_name, check_command in checks:
            self.log(f"Checking {check_name}...")
            
            try:
                if callable(check_command):
                    result = check_command()
                    if not result:
                        self.log(f"❌ {check_name} check failed", 'ERROR')
                        return False
                else:
                    self.run_command(check_command)
                
                self.log(f"✅ {check_name} check passed")
                
            except Exception as e:
                self.log(f"❌ {check_name} check failed: {str(e)}", 'ERROR')
                return False
        
        return True
    
    def _check_env_vars(self) -> bool:
        """Check required environment variables."""
        required_vars = [
            'DJANGO_SECRET_KEY',
            'DATABASE_URL',
            'PROVIDER_AUTH_TOKEN_SECRET',
            'PATIENT_AUTH_TOKEN_SECRET',
            'OPERATIONS_AUTH_TOKEN_SECRET',
            'ORG_CONTEXT_TOKEN_SECRET',
        ]
        
        missing_vars = []
        for var in required_vars:
            if not os.getenv(var):
                missing_vars.append(var)
        
        if missing_vars:
            self.log(f"Missing environment variables: {missing_vars}", 'ERROR')
            return False
        
        return True
    
    def backup_database(self) -> str:
        """Create database backup before deployment."""
        self.log("Creating database backup...")
        
        backup_file = f"backup-{self.deployment_id}.sql"
        
        # This would need to be adapted based on your database type
        # For PostgreSQL:
        database_url = os.getenv('DATABASE_URL')
        if database_url and 'postgresql' in database_url:
            self.run_command(f"pg_dump {database_url} > {backup_file}")
        else:
            self.log("Database backup skipped - not PostgreSQL", 'WARNING')
            return None
        
        self.log(f"Database backup created: {backup_file}")
        return backup_file
    
    def run_migrations(self) -> bool:
        """Run database migrations."""
        self.log("Running database migrations...")
        
        try:
            # Check for pending migrations
            result = self.run_command("python manage.py showmigrations --plan", check=False)
            if "[ ]" in result.stdout:
                self.log("Pending migrations found, applying...")
                self.run_command("python manage.py migrate")
                self.log("✅ Migrations applied successfully")
            else:
                self.log("✅ No pending migrations")
            
            return True
            
        except Exception as e:
            self.log(f"❌ Migration failed: {str(e)}", 'ERROR')
            return False
    
    def setup_service_accounts(self) -> bool:
        """Set up service accounts from environment."""
        self.log("Setting up service accounts...")
        
        try:
            # Load service accounts from environment
            self.run_command("python manage.py load_service_accounts --force")
            self.log("✅ Service accounts loaded successfully")
            
            # Validate service configuration
            result = self.run_command("python -c \"from users.service_loader import validate_service_configuration; import json; print(json.dumps(validate_service_configuration()))\"")
            
            validation = json.loads(result.stdout.strip())
            if validation['valid']:
                self.log("✅ Service configuration validation passed")
            else:
                self.log(f"❌ Service configuration validation failed: {validation['issues']}", 'ERROR')
                return False
            
            return True
            
        except Exception as e:
            self.log(f"❌ Service account setup failed: {str(e)}", 'ERROR')
            return False
    
    def create_operations_user(self) -> bool:
        """Create initial OPERATIONS user if needed."""
        self.log("Checking for OPERATIONS user...")
        
        try:
            # Check if OPERATIONS user exists
            result = self.run_command(
                "python -c \"from users.models import User, UserRole; from django.contrib.auth import get_user_model; User = get_user_model(); ops_role = UserRole.objects.filter(name='OPERATIONS').first(); print('EXISTS' if ops_role and User.objects.filter(role_assignments__role=ops_role, role_assignments__is_active=True).exists() else 'MISSING')\"",
                check=False
            )
            
            if "MISSING" in result.stdout:
                self.log("Creating initial OPERATIONS user...")
                
                # Get credentials from environment or prompt
                ops_email = os.getenv('INITIAL_OPS_EMAIL', 'ops@afyaflow.com')
                ops_password = os.getenv('INITIAL_OPS_PASSWORD')
                
                if not ops_password:
                    self.log("❌ INITIAL_OPS_PASSWORD environment variable required", 'ERROR')
                    return False
                
                self.run_command(f"python manage.py create_operations_user --email {ops_email} --first-name Operations --last-name Admin --password {ops_password} --no-input")
                self.log("✅ OPERATIONS user created successfully")
            else:
                self.log("✅ OPERATIONS user already exists")
            
            return True
            
        except Exception as e:
            self.log(f"❌ OPERATIONS user setup failed: {str(e)}", 'ERROR')
            return False
    
    def validate_deployment(self) -> bool:
        """Validate the deployment."""
        self.log("Validating deployment...")
        
        validation_checks = [
            ("Django check", "python manage.py check"),
            ("Database connectivity", "python manage.py check --database default"),
            ("Service accounts", self._validate_service_accounts),
            ("Token generation", self._validate_token_generation),
        ]
        
        for check_name, check_command in validation_checks:
            self.log(f"Validating {check_name}...")
            
            try:
                if callable(check_command):
                    result = check_command()
                    if not result:
                        self.log(f"❌ {check_name} validation failed", 'ERROR')
                        return False
                else:
                    self.run_command(check_command)
                
                self.log(f"✅ {check_name} validation passed")
                
            except Exception as e:
                self.log(f"❌ {check_name} validation failed: {str(e)}", 'ERROR')
                return False
        
        return True
    
    def _validate_service_accounts(self) -> bool:
        """Validate service accounts are properly configured."""
        try:
            result = self.run_command(
                "python -c \"from users.models import ServiceAccount; print(f'Active: {ServiceAccount.objects.filter(is_active=True).count()}, Total: {ServiceAccount.objects.count()}')\""
            )
            self.log(f"Service accounts status: {result.stdout.strip()}")
            return True
        except:
            return False
    
    def _validate_token_generation(self) -> bool:
        """Validate token generation works."""
        try:
            self.run_command(
                "python -c \"from users.models import User; from users.gateway_jwt import GatewayJWTManager; user = User.objects.filter(is_active=True).first(); token = GatewayJWTManager.create_auth_token(user) if user else None; print('Token generation: OK' if token else 'Token generation: FAILED')\""
            )
            return True
        except:
            return False
    
    def deploy(self) -> bool:
        """Execute the full deployment process."""
        self.log(f"Starting production deployment {self.deployment_id}")
        
        steps = [
            ("Prerequisites check", self.check_prerequisites),
            ("Database backup", lambda: self.backup_database() is not None),
            ("Database migrations", self.run_migrations),
            ("Service account setup", self.setup_service_accounts),
            ("OPERATIONS user setup", self.create_operations_user),
            ("Deployment validation", self.validate_deployment),
        ]
        
        for step_name, step_function in steps:
            self.log(f"Executing step: {step_name}")
            
            try:
                if not step_function():
                    self.log(f"❌ Deployment failed at step: {step_name}", 'ERROR')
                    return False
                
                self.log(f"✅ Step completed: {step_name}")
                
            except Exception as e:
                self.log(f"❌ Step failed: {step_name} - {str(e)}", 'ERROR')
                return False
        
        self.log(f"🎉 Deployment {self.deployment_id} completed successfully!")
        return True
    
    def rollback(self, backup_file: str) -> bool:
        """Rollback deployment using backup."""
        self.log(f"Rolling back deployment using backup: {backup_file}")
        
        try:
            if backup_file and os.path.exists(backup_file):
                database_url = os.getenv('DATABASE_URL')
                if database_url and 'postgresql' in database_url:
                    self.run_command(f"psql {database_url} < {backup_file}")
                    self.log("✅ Database rollback completed")
                else:
                    self.log("❌ Cannot rollback - unsupported database", 'ERROR')
                    return False
            else:
                self.log("❌ Backup file not found", 'ERROR')
                return False
            
            return True
            
        except Exception as e:
            self.log(f"❌ Rollback failed: {str(e)}", 'ERROR')
            return False


def main():
    """Main deployment script."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Afyaflow Auth Service Production Deployment')
    parser.add_argument('--environment', default='production', help='Deployment environment')
    parser.add_argument('--rollback', help='Rollback using specified backup file')
    parser.add_argument('--dry-run', action='store_true', help='Perform dry run without actual deployment')
    
    args = parser.parse_args()
    
    deployer = ProductionDeployer(args.environment)
    
    if args.rollback:
        success = deployer.rollback(args.rollback)
    elif args.dry_run:
        deployer.log("Performing dry run...")
        success = deployer.check_prerequisites()
    else:
        success = deployer.deploy()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
