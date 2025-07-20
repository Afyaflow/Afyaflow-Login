"""
Management command to create OPERATIONS users for system administration.
"""

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.db import transaction
from users.models import UserRole, UserRoleAssignment
import getpass

User = get_user_model()


class Command(BaseCommand):
    help = 'Create an OPERATIONS user with system-wide administrative privileges'

    def add_arguments(self, parser):
        parser.add_argument(
            '--email',
            type=str,
            help='Email address for the operations user',
        )
        parser.add_argument(
            '--first-name',
            type=str,
            help='First name of the operations user',
        )
        parser.add_argument(
            '--last-name',
            type=str,
            help='Last name of the operations user',
        )
        parser.add_argument(
            '--password',
            type=str,
            help='Password for the operations user (will prompt if not provided)',
        )
        parser.add_argument(
            '--no-input',
            action='store_true',
            help='Do not prompt for input (requires all fields to be provided)',
        )

    def handle(self, *args, **options):
        # Get or prompt for required information
        email = options.get('email')
        first_name = options.get('first_name')
        last_name = options.get('last_name')
        password = options.get('password')
        no_input = options.get('no_input')

        if not no_input:
            if not email:
                email = input('Email address: ')
            if not first_name:
                first_name = input('First name: ')
            if not last_name:
                last_name = input('Last name: ')
            if not password:
                password = getpass.getpass('Password: ')
                password_confirm = getpass.getpass('Password (again): ')
                if password != password_confirm:
                    raise CommandError('Passwords do not match')
        
        # Validate required fields
        if not all([email, first_name, last_name, password]):
            raise CommandError('All fields (email, first_name, last_name, password) are required')

        try:
            with transaction.atomic():
                # Check if user already exists
                if User.objects.filter(email=email).exists():
                    raise CommandError(f'User with email {email} already exists')

                # Get or create OPERATIONS role
                operations_role, created = UserRole.objects.get_or_create(
                    name='OPERATIONS',
                    defaults={
                        'description': 'Operations and system administration role with cross-tenant access',
                        'permissions': [
                            'view_all_users',
                            'view_system_logs',
                            'manage_system_settings',
                            'access_admin_interface',
                            'cross_tenant_access',
                            'system_maintenance',
                            'technical_support',
                            'service_account_management',
                            'global_monitoring'
                        ],
                        'is_active': True
                    }
                )

                if created:
                    self.stdout.write(
                        self.style.SUCCESS(f'Created OPERATIONS role')
                    )

                # Create the user
                user = User.objects.create_user(
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    password=password,
                    is_active=True,
                    email_verified=True  # Operations users are pre-verified
                )

                # Assign OPERATIONS role
                role_assignment = UserRoleAssignment.objects.create(
                    user=user,
                    role=operations_role,
                    is_active=True
                )

                # Set as primary role
                user.primary_role = operations_role
                user.save(update_fields=['primary_role'])

                self.stdout.write(
                    self.style.SUCCESS(
                        f'Successfully created OPERATIONS user: {email}\n'
                        f'User ID: {user.id}\n'
                        f'Role Assignment ID: {role_assignment.id}\n'
                        f'Permissions: {operations_role.permissions}'
                    )
                )

                # Display security recommendations
                self.stdout.write(
                    self.style.WARNING(
                        '\nSECURITY RECOMMENDATIONS:\n'
                        '1. Enable MFA for this user immediately\n'
                        '2. Use a strong, unique password\n'
                        '3. Regularly rotate credentials\n'
                        '4. Monitor access logs for this user\n'
                        '5. Limit access to necessary systems only'
                    )
                )

        except Exception as e:
            raise CommandError(f'Error creating OPERATIONS user: {str(e)}')

    def get_operations_role_info(self):
        """Display information about the OPERATIONS role."""
        try:
            role = UserRole.objects.get(name='OPERATIONS')
            self.stdout.write(f'OPERATIONS Role Information:')
            self.stdout.write(f'Description: {role.description}')
            self.stdout.write(f'Permissions: {role.permissions}')
            self.stdout.write(f'Active: {role.is_active}')
            
            # Count existing operations users
            operations_users = User.objects.filter(
                role_assignments__role=role,
                role_assignments__is_active=True,
                is_active=True
            ).count()
            self.stdout.write(f'Existing OPERATIONS users: {operations_users}')
            
        except UserRole.DoesNotExist:
            self.stdout.write(
                self.style.WARNING('OPERATIONS role does not exist yet')
            )
