from django.core.management.base import BaseCommand, CommandError
from users.models import RegisteredClient
from users.credential_rotation import CredentialRotationManager, RotationScheduler
import json


class Command(BaseCommand):
    help = 'Rotate client credentials for security purposes'

    def add_arguments(self, parser):
        parser.add_argument(
            '--client-id',
            type=str,
            help='Specific client ID to rotate credentials for'
        )
        parser.add_argument(
            '--all-due',
            action='store_true',
            help='Rotate credentials for all clients that are due for rotation'
        )
        parser.add_argument(
            '--emergency',
            action='store_true',
            help='Perform emergency rotation (revokes all tokens immediately)'
        )
        parser.add_argument(
            '--reason',
            type=str,
            default='Manual rotation',
            help='Reason for credential rotation'
        )
        parser.add_argument(
            '--output-format',
            choices=['json', 'text'],
            default='text',
            help='Output format for results'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be rotated without actually doing it'
        )

    def handle(self, *args, **options):
        client_id = options['client_id']
        all_due = options['all_due']
        emergency = options['emergency']
        reason = options['reason']
        output_format = options['output_format']
        dry_run = options['dry_run']

        if not client_id and not all_due:
            raise CommandError('Must specify either --client-id or --all-due')

        if client_id and all_due:
            raise CommandError('Cannot specify both --client-id and --all-due')

        try:
            if client_id:
                self._rotate_single_client(client_id, emergency, reason, output_format, dry_run)
            else:
                self._rotate_all_due_clients(emergency, reason, output_format, dry_run)
        except Exception as e:
            raise CommandError(f'Credential rotation failed: {str(e)}')

    def _rotate_single_client(self, client_id, emergency, reason, output_format, dry_run):
        """Rotate credentials for a single client."""
        try:
            client = RegisteredClient.objects.get(client_id=client_id)
        except RegisteredClient.DoesNotExist:
            raise CommandError(f'Client with ID {client_id} not found')

        if dry_run:
            self._show_dry_run_single(client, emergency, reason, output_format)
            return

        rotation_manager = CredentialRotationManager(client)
        
        if emergency:
            result = rotation_manager.emergency_rotation(reason)
            self.stdout.write(
                self.style.WARNING(f'Emergency credential rotation completed for: {client.client_name}')
            )
        else:
            result = rotation_manager.rotate_credentials(reason)
            self.stdout.write(
                self.style.SUCCESS(f'Credential rotation completed for: {client.client_name}')
            )

        if output_format == 'json':
            self.stdout.write(json.dumps(result, indent=2))
        else:
            self._output_single_result_text(result, emergency)

    def _rotate_all_due_clients(self, emergency, reason, output_format, dry_run):
        """Rotate credentials for all clients due for rotation."""
        if dry_run:
            self._show_dry_run_all(emergency, reason, output_format)
            return

        if emergency:
            # For emergency rotation of all clients, we need explicit confirmation
            confirm = input('Are you sure you want to perform EMERGENCY rotation for ALL clients? (type "EMERGENCY" to confirm): ')
            if confirm != 'EMERGENCY':
                self.stdout.write('Emergency rotation cancelled.')
                return

        result = RotationScheduler.rotate_all_due_clients()

        if output_format == 'json':
            self.stdout.write(json.dumps(result, indent=2))
        else:
            self._output_all_results_text(result)

    def _show_dry_run_single(self, client, emergency, reason, output_format):
        """Show what would happen for a single client rotation."""
        schedule = RotationScheduler.get_rotation_schedule(client)
        
        if output_format == 'json':
            dry_run_result = {
                'action': 'emergency_rotation' if emergency else 'standard_rotation',
                'client': {
                    'client_id': str(client.client_id),
                    'client_name': client.client_name,
                    'client_type': client.client_type
                },
                'reason': reason,
                'schedule': schedule,
                'would_rotate': True
            }
            self.stdout.write(json.dumps(dry_run_result, indent=2))
        else:
            self.stdout.write(f'DRY RUN - Would rotate credentials for: {client.client_name}')
            self.stdout.write(f'  Client ID: {client.client_id}')
            self.stdout.write(f'  Client Type: {client.client_type}')
            self.stdout.write(f'  Rotation Type: {"Emergency" if emergency else "Standard"}')
            self.stdout.write(f'  Reason: {reason}')
            self.stdout.write(f'  Last Rotation: {schedule["last_rotation"] or "Never"}')
            self.stdout.write(f'  Days Until Due: {schedule["days_until_rotation"]}')

    def _show_dry_run_all(self, emergency, reason, output_format):
        """Show what would happen for all due clients."""
        due_clients = []
        
        for client in RegisteredClient.objects.filter(is_active=True):
            if RotationScheduler.should_rotate_credentials(client):
                due_clients.append(client)

        if output_format == 'json':
            dry_run_result = {
                'action': 'emergency_rotation_all' if emergency else 'standard_rotation_all',
                'reason': reason,
                'total_due_clients': len(due_clients),
                'clients': [
                    {
                        'client_id': str(client.client_id),
                        'client_name': client.client_name,
                        'client_type': client.client_type,
                        'schedule': RotationScheduler.get_rotation_schedule(client)
                    }
                    for client in due_clients
                ]
            }
            self.stdout.write(json.dumps(dry_run_result, indent=2))
        else:
            self.stdout.write(f'DRY RUN - Would rotate credentials for {len(due_clients)} clients:')
            self.stdout.write('')
            
            if not due_clients:
                self.stdout.write('No clients are currently due for rotation.')
                return
            
            for client in due_clients:
                schedule = RotationScheduler.get_rotation_schedule(client)
                self.stdout.write(f'  - {client.client_name} ({client.client_type})')
                self.stdout.write(f'    Client ID: {client.client_id}')
                self.stdout.write(f'    Days Overdue: {abs(schedule["days_until_rotation"]) if schedule["rotation_overdue"] else 0}')
                self.stdout.write('')

    def _output_single_result_text(self, result, emergency):
        """Output single client rotation result in text format."""
        self.stdout.write('')
        self.stdout.write('Rotation Details:')
        self.stdout.write(f'  Client ID: {result["client_id"]}')
        self.stdout.write(f'  Rotation Time: {result["rotation_record"]["rotation_time"]}')
        self.stdout.write(f'  Reason: {result["rotation_record"]["reason"]}')
        
        if emergency and 'emergency_actions' in result:
            self.stdout.write('')
            self.stdout.write('Emergency Actions:')
            self.stdout.write(f'  Revoked Tokens: {result["emergency_actions"]["revoked_tokens_count"]}')
            self.stdout.write(f'  Immediate Effect: {result["emergency_actions"]["immediate_effect"]}')
        
        self.stdout.write('')
        self.stdout.write(self.style.WARNING('IMPORTANT: Store these new credentials securely!'))
        self.stdout.write('')
        self.stdout.write('New Credentials:')
        self.stdout.write(f'  API Key: {result["new_credentials"]["api_key"]}')
        self.stdout.write('')
        self.stdout.write('New JWT Signing Key:')
        self.stdout.write(result["new_credentials"]["signing_key"])
        
        if not emergency and 'transition_period' in result:
            self.stdout.write('')
            self.stdout.write('Transition Period Information:')
            self.stdout.write(f'  Old credentials valid until: {result["transition_period"]["cleanup_time"]}')
            self.stdout.write('  Old signing key available for token validation during transition')

    def _output_all_results_text(self, result):
        """Output all clients rotation result in text format."""
        self.stdout.write(f'Credential Rotation Summary:')
        self.stdout.write(f'  Total clients due: {result["total_due"]}')
        self.stdout.write(f'  Successful rotations: {result["successful_rotations"]}')
        self.stdout.write(f'  Failed rotations: {result["failed_rotations"]}')
        self.stdout.write('')
        
        if result["results"]:
            self.stdout.write('Successful Rotations:')
            for rotation in result["results"]:
                self.stdout.write(f'  ✓ {rotation["client_name"]} ({rotation["client_id"][:8]}...)')
        
        if result["errors"]:
            self.stdout.write('')
            self.stdout.write(self.style.ERROR('Failed Rotations:'))
            for error in result["errors"]:
                self.stdout.write(f'  ✗ {error["client_name"]}: {error["error"]}')
        
        self.stdout.write('')
        self.stdout.write(f'Execution completed at: {result["execution_time"]}')
        
        if result["successful_rotations"] > 0:
            self.stdout.write('')
            self.stdout.write(self.style.WARNING(
                'IMPORTANT: New credentials have been generated. '
                'Use the manage_clients command to retrieve them.'
            ))
