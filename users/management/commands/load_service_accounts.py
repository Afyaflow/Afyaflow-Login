"""
Management command to load service accounts from environment variables.
"""

from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from django.db import transaction
from users.models import ServiceAccount


class Command(BaseCommand):
    help = 'Load service accounts from environment variables'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be created without actually creating anything',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Update existing service accounts with new configuration',
        )

    def handle(self, *args, **options):
        dry_run = options.get('dry_run')
        force = options.get('force')

        # Get service account IDs from settings
        service_ids = getattr(settings, 'SERVICE_ACCOUNT_IDS', [])
        
        if not service_ids:
            self.stdout.write(
                self.style.WARNING(
                    'No service account IDs found in SERVICE_ACCOUNT_IDS setting.\n'
                    'Make sure to set SERVICE_ACCOUNT_IDS in your environment variables.'
                )
            )
            return

        self.stdout.write(f'Found {len(service_ids)} service account(s) to process')

        created_count = 0
        updated_count = 0
        skipped_count = 0
        errors = []

        try:
            with transaction.atomic():
                for service_id in service_ids:
                    try:
                        result = self.process_service_account(service_id, dry_run, force)
                        
                        if result == 'created':
                            created_count += 1
                        elif result == 'updated':
                            updated_count += 1
                        elif result == 'skipped':
                            skipped_count += 1
                            
                    except Exception as e:
                        error_msg = f'Error processing {service_id}: {str(e)}'
                        errors.append(error_msg)
                        self.stdout.write(self.style.ERROR(error_msg))

                if dry_run:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f'\nDRY RUN COMPLETE:\n'
                            f'Would create: {created_count}\n'
                            f'Would update: {updated_count}\n'
                            f'Would skip: {skipped_count}\n'
                            f'Errors: {len(errors)}'
                        )
                    )
                    # Rollback transaction for dry run
                    transaction.set_rollback(True)
                else:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f'\nCOMPLETE:\n'
                            f'Created: {created_count}\n'
                            f'Updated: {updated_count}\n'
                            f'Skipped: {skipped_count}\n'
                            f'Errors: {len(errors)}'
                        )
                    )

        except Exception as e:
            raise CommandError(f'Transaction failed: {str(e)}')

        if errors:
            self.stdout.write(
                self.style.ERROR(f'\nErrors encountered:\n' + '\n'.join(errors))
            )

    def process_service_account(self, service_id, dry_run=False, force=False):
        """Process a single service account."""
        
        # Normalize service ID for environment variable names
        normalized_id = service_id.upper().replace('-', '_').replace('.', '_')
        
        # Get configuration from environment
        service_type = getattr(settings, f'SERVICE_ACCOUNT_{normalized_id}_TYPE', None)
        permissions_str = getattr(settings, f'SERVICE_ACCOUNT_{normalized_id}_PERMISSIONS', '')
        
        if not service_type:
            self.stdout.write(
                self.style.WARNING(
                    f'No service type found for {service_id}. '
                    f'Set SERVICE_ACCOUNT_{normalized_id}_TYPE in environment.'
                )
            )
            return 'skipped'

        # Parse permissions
        permissions = [p.strip() for p in permissions_str.split(',') if p.strip()]

        # Check if service account already exists
        existing = ServiceAccount.objects.filter(service_id=service_id).first()

        if existing:
            if not force:
                self.stdout.write(
                    self.style.WARNING(
                        f'Service account {service_id} already exists. Use --force to update.'
                    )
                )
                return 'skipped'
            else:
                # Update existing
                if not dry_run:
                    existing.service_type = service_type
                    existing.permissions = permissions
                    existing.is_active = True
                    existing.save()
                
                self.stdout.write(
                    self.style.SUCCESS(
                        f'{"[DRY RUN] " if dry_run else ""}Updated service account: {service_id}\n'
                        f'  Type: {service_type}\n'
                        f'  Permissions: {permissions}'
                    )
                )
                return 'updated'
        else:
            # Create new
            if not dry_run:
                ServiceAccount.objects.create(
                    service_id=service_id,
                    service_type=service_type,
                    permissions=permissions,
                    is_active=True
                )
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'{"[DRY RUN] " if dry_run else ""}Created service account: {service_id}\n'
                    f'  Type: {service_type}\n'
                    f'  Permissions: {permissions}'
                )
            )
            return 'created'

    def list_existing_service_accounts(self):
        """List all existing service accounts."""
        accounts = ServiceAccount.objects.all().order_by('service_id')
        
        if not accounts:
            self.stdout.write('No service accounts found in database.')
            return

        self.stdout.write(f'\nExisting service accounts ({accounts.count()}):')
        for account in accounts:
            status = "ACTIVE" if account.is_active else "INACTIVE"
            self.stdout.write(
                f'  {account.service_id} ({account.service_type}) - {status}\n'
                f'    Permissions: {account.permissions}'
            )
