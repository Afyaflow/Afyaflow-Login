"""
Management command to load service accounts from environment variables.
"""

from django.core.management.base import BaseCommand, CommandError
from users.service_loader import get_service_loader


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

        # Use the service loader
        loader = get_service_loader()

        if dry_run:
            # For dry run, just validate configuration
            validation = loader.validate_configuration()

            self.stdout.write(f"Configuration validation:")
            self.stdout.write(f"Valid: {validation['valid']}")

            if validation['issues']:
                self.stdout.write(self.style.WARNING("Issues found:"))
                for issue in validation['issues']:
                    self.stdout.write(f"  - {issue}")

            if validation['warnings']:
                self.stdout.write(self.style.WARNING("Warnings:"))
                for warning in validation['warnings']:
                    self.stdout.write(f"  - {warning}")

            return

        # Load service accounts
        result = loader.load_service_accounts(force_update=force)

        if result['success']:
            self.stdout.write(
                self.style.SUCCESS(
                    f'\nCOMPLETE:\n'
                    f'Created: {result["created_count"]}\n'
                    f'Updated: {result["updated_count"]}\n'
                    f'Load time: {result["load_time"]:.3f}s'
                )
            )
        else:
            self.stdout.write(self.style.ERROR("Service account loading failed"))

        if result.get('errors'):
            self.stdout.write(self.style.ERROR("Errors encountered:"))
            for error in result['errors']:
                self.stdout.write(f"  - {error}")
