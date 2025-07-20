"""
Management command to help clients migrate to the new gateway-compliant token format.
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from users.models import RegisteredClient
from users.dual_jwt import DualJWTManager, MigrationMonitor
from datetime import datetime, timedelta
from django.utils import timezone

class Command(BaseCommand):
    help = 'Manage client migration to gateway-compliant token format'

    def add_arguments(self, parser):
        parser.add_argument(
            'action',
            choices=['status', 'start', 'complete', 'rollback', 'monitor'],
            help='Migration action to perform'
        )
        parser.add_argument(
            '--client-name',
            type=str,
            help='Name of the client to migrate',
        )
        parser.add_argument(
            '--client-id',
            type=str,
            help='ID of the client to migrate',
        )
        parser.add_argument(
            '--deadline',
            type=str,
            help='Legacy support deadline (YYYY-MM-DD format)',
        )
        parser.add_argument(
            '--all-clients',
            action='store_true',
            help='Apply action to all clients',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force the migration without confirmation',
        )

    def handle(self, *args, **options):
        action = options['action']
        
        if action == 'status':
            self.show_migration_status(options)
        elif action == 'start':
            self.start_migration(options)
        elif action == 'complete':
            self.complete_migration(options)
        elif action == 'rollback':
            self.rollback_migration(options)
        elif action == 'monitor':
            self.monitor_migration(options)

    def show_migration_status(self, options):
        """Show current migration status."""
        if options.get('client_name') or options.get('client_id'):
            # Show specific client status
            client = self.get_client(options)
            if client:
                self.show_client_status(client)
        else:
            # Show overall migration progress
            self.show_overall_status()

    def show_client_status(self, client):
        """Show status for a specific client."""
        dual_manager = DualJWTManager(client)
        status = dual_manager.get_migration_status()
        
        self.stdout.write(f"\n📋 Client Migration Status: {client.client_name}")
        self.stdout.write(f"   Client ID: {status['client_id']}")
        self.stdout.write(f"   Migration Status: {status['migration_status']}")
        self.stdout.write(f"   Supports New Format: {status['supports_new_format']}")
        self.stdout.write(f"   Legacy Support Until: {status['legacy_support_until'] or 'Not set'}")
        
        # Check for deprecation warnings
        warning = dual_manager.get_deprecation_warning()
        if warning:
            self.stdout.write(self.style.WARNING(f"   ⚠️  {warning}"))
        
        # Show recommended next steps
        self.show_recommendations(client, status)

    def show_overall_status(self):
        """Show overall migration progress."""
        progress = MigrationMonitor.get_migration_progress()
        
        self.stdout.write(f"\n📊 Overall Migration Progress")
        self.stdout.write(f"   Total Clients: {progress['total_clients']}")
        self.stdout.write(f"   Progress: {progress['progress_percentage']}%")
        self.stdout.write(f"   Migration Complete: {progress['migration_complete']}")
        
        self.stdout.write(f"\n📈 Status Breakdown:")
        for status, count in progress['status_counts'].items():
            self.stdout.write(f"   {status}: {count} clients")
        
        if progress['clients_needing_migration'] > 0:
            self.stdout.write(
                self.style.WARNING(
                    f"\n⚠️  {progress['clients_needing_migration']} clients still need migration"
                )
            )

    def show_recommendations(self, client, status):
        """Show migration recommendations for a client."""
        current_status = status['migration_status']
        
        self.stdout.write(f"\n💡 Recommendations:")
        
        if current_status == 'LEGACY':
            self.stdout.write("   1. Start migration by moving to DUAL support")
            self.stdout.write("   2. Test new token format with your application")
            self.stdout.write("   3. Set a legacy support deadline")
        elif current_status == 'DUAL':
            self.stdout.write("   1. Verify new token format works correctly")
            self.stdout.write("   2. Complete migration to NEW format only")
            self.stdout.write("   3. Remove legacy token handling from your code")
        elif current_status == 'NEW':
            self.stdout.write("   ✅ Migration complete! No further action needed.")

    def start_migration(self, options):
        """Start migration for a client (LEGACY -> DUAL)."""
        client = self.get_client(options)
        if not client:
            return

        if client.migration_status != 'LEGACY':
            raise CommandError(f"Client {client.client_name} is not in LEGACY status")

        # Set deadline if provided
        deadline = None
        if options.get('deadline'):
            try:
                deadline = datetime.strptime(options['deadline'], '%Y-%m-%d')
                deadline = timezone.make_aware(deadline)
            except ValueError:
                raise CommandError("Invalid deadline format. Use YYYY-MM-DD")

        if not options.get('force'):
            self.stdout.write(f"Starting migration for client: {client.client_name}")
            self.stdout.write("This will enable DUAL token support (both legacy and new formats)")
            if deadline:
                self.stdout.write(f"Legacy support will end on: {deadline.date()}")
            
            confirm = input("Continue? (y/N): ")
            if confirm.lower() != 'y':
                self.stdout.write("Migration cancelled")
                return

        try:
            with transaction.atomic():
                dual_manager = DualJWTManager(client)
                success = dual_manager.update_migration_status('DUAL')
                
                if deadline:
                    client.legacy_token_support_until = deadline
                    client.save(update_fields=['legacy_token_support_until'])

                if success:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"✅ Migration started for {client.client_name}"
                        )
                    )
                    self.stdout.write("Client now supports both legacy and new token formats")
                else:
                    raise CommandError("Failed to update migration status")

        except Exception as e:
            raise CommandError(f"Migration failed: {str(e)}")

    def complete_migration(self, options):
        """Complete migration for a client (DUAL -> NEW)."""
        client = self.get_client(options)
        if not client:
            return

        if client.migration_status != 'DUAL':
            raise CommandError(f"Client {client.client_name} is not in DUAL status")

        if not options.get('force'):
            self.stdout.write(f"Completing migration for client: {client.client_name}")
            self.stdout.write("This will disable legacy token support")
            self.stdout.write("⚠️  Make sure your application fully supports the new token format!")
            
            confirm = input("Continue? (y/N): ")
            if confirm.lower() != 'y':
                self.stdout.write("Migration cancelled")
                return

        try:
            with transaction.atomic():
                dual_manager = DualJWTManager(client)
                success = dual_manager.update_migration_status('NEW')

                if success:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"✅ Migration completed for {client.client_name}"
                        )
                    )
                    self.stdout.write("Client now only supports new gateway-compliant tokens")
                else:
                    raise CommandError("Failed to update migration status")

        except Exception as e:
            raise CommandError(f"Migration completion failed: {str(e)}")

    def rollback_migration(self, options):
        """Rollback migration for a client."""
        client = self.get_client(options)
        if not client:
            return

        current_status = client.migration_status
        
        if current_status == 'LEGACY':
            raise CommandError(f"Client {client.client_name} is already in LEGACY status")

        target_status = 'DUAL' if current_status == 'NEW' else 'LEGACY'

        if not options.get('force'):
            self.stdout.write(f"Rolling back migration for client: {client.client_name}")
            self.stdout.write(f"Status will change from {current_status} to {target_status}")
            
            confirm = input("Continue? (y/N): ")
            if confirm.lower() != 'y':
                self.stdout.write("Rollback cancelled")
                return

        try:
            with transaction.atomic():
                dual_manager = DualJWTManager(client)
                success = dual_manager.update_migration_status(target_status)

                if success:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"✅ Migration rolled back for {client.client_name}"
                        )
                    )
                else:
                    raise CommandError("Failed to rollback migration status")

        except Exception as e:
            raise CommandError(f"Migration rollback failed: {str(e)}")

    def monitor_migration(self, options):
        """Monitor migration progress and show warnings."""
        progress = MigrationMonitor.get_migration_progress()
        
        self.stdout.write("🔍 Migration Monitoring Report")
        self.stdout.write(f"Generated: {datetime.now().isoformat()}")
        
        # Overall progress
        self.show_overall_status()
        
        # Clients needing attention
        clients_needing_attention = RegisteredClient.objects.filter(
            is_active=True,
            migration_status__in=['LEGACY', 'DUAL']
        )
        
        if clients_needing_attention.exists():
            self.stdout.write(f"\n⚠️  Clients Needing Attention:")
            
            for client in clients_needing_attention:
                dual_manager = DualJWTManager(client)
                warning = dual_manager.get_deprecation_warning()
                
                if warning or client.migration_status == 'LEGACY':
                    self.stdout.write(f"\n   📱 {client.client_name}")
                    self.stdout.write(f"      Status: {client.migration_status}")
                    if warning:
                        self.stdout.write(f"      Warning: {warning}")
        
        # Migration timeline
        self.show_migration_timeline()

    def show_migration_timeline(self):
        """Show migration timeline and deadlines."""
        clients_with_deadlines = RegisteredClient.objects.filter(
            is_active=True,
            legacy_token_support_until__isnull=False
        ).order_by('legacy_token_support_until')
        
        if clients_with_deadlines.exists():
            self.stdout.write(f"\n📅 Migration Timeline:")
            
            for client in clients_with_deadlines:
                days_remaining = (client.legacy_token_support_until - timezone.now()).days
                status_icon = "🔴" if days_remaining < 7 else "🟡" if days_remaining < 30 else "🟢"
                
                self.stdout.write(
                    f"   {status_icon} {client.client_name}: "
                    f"{client.legacy_token_support_until.date()} "
                    f"({days_remaining} days)"
                )

    def get_client(self, options):
        """Get client by name or ID."""
        client_name = options.get('client_name')
        client_id = options.get('client_id')
        
        if not client_name and not client_id:
            raise CommandError("Either --client-name or --client-id is required")
        
        try:
            if client_id:
                client = RegisteredClient.objects.get(client_id=client_id, is_active=True)
            else:
                client = RegisteredClient.objects.get(client_name=client_name, is_active=True)
            
            return client
            
        except RegisteredClient.DoesNotExist:
            identifier = client_id or client_name
            raise CommandError(f"Client not found: {identifier}")
        except RegisteredClient.MultipleObjectsReturned:
            raise CommandError(f"Multiple clients found with name: {client_name}")
