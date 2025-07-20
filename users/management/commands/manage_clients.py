from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from users.models import RegisteredClient
from users.client_utils import ClientCredentialManager
import json
from tabulate import tabulate


class Command(BaseCommand):
    help = 'Manage registered client applications'

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(dest='action', help='Available actions')
        
        # List clients
        list_parser = subparsers.add_parser('list', help='List all registered clients')
        list_parser.add_argument(
            '--format',
            choices=['table', 'json'],
            default='table',
            help='Output format'
        )
        list_parser.add_argument(
            '--active-only',
            action='store_true',
            help='Show only active clients'
        )
        
        # Show client details
        show_parser = subparsers.add_parser('show', help='Show detailed client information')
        show_parser.add_argument('client_id', help='Client ID to show')
        
        # Activate/deactivate client
        activate_parser = subparsers.add_parser('activate', help='Activate a client')
        activate_parser.add_argument('client_id', help='Client ID to activate')
        
        deactivate_parser = subparsers.add_parser('deactivate', help='Deactivate a client')
        deactivate_parser.add_argument('client_id', help='Client ID to deactivate')
        
        # Rotate credentials
        rotate_parser = subparsers.add_parser('rotate', help='Rotate client credentials')
        rotate_parser.add_argument('client_id', help='Client ID to rotate credentials for')
        rotate_parser.add_argument(
            '--output-format',
            choices=['json', 'text'],
            default='text',
            help='Output format for new credentials'
        )
        
        # Update client
        update_parser = subparsers.add_parser('update', help='Update client configuration')
        update_parser.add_argument('client_id', help='Client ID to update')
        update_parser.add_argument('--name', help='New client name')
        update_parser.add_argument('--domains', nargs='*', help='New allowed domains')
        update_parser.add_argument('--rate-limit', type=int, help='New rate limit')
        
        # Delete client
        delete_parser = subparsers.add_parser('delete', help='Delete a client')
        delete_parser.add_argument('client_id', help='Client ID to delete')
        delete_parser.add_argument(
            '--force',
            action='store_true',
            help='Force deletion without confirmation'
        )

    def handle(self, *args, **options):
        action = options['action']
        
        if not action:
            self.print_help('manage_clients', '')
            return
        
        try:
            if action == 'list':
                self._list_clients(options)
            elif action == 'show':
                self._show_client(options['client_id'])
            elif action == 'activate':
                self._activate_client(options['client_id'])
            elif action == 'deactivate':
                self._deactivate_client(options['client_id'])
            elif action == 'rotate':
                self._rotate_credentials(options['client_id'], options['output_format'])
            elif action == 'update':
                self._update_client(options)
            elif action == 'delete':
                self._delete_client(options['client_id'], options['force'])
        except Exception as e:
            raise CommandError(f'Failed to {action} client: {str(e)}')

    def _list_clients(self, options):
        """List all registered clients."""
        queryset = RegisteredClient.objects.all()
        
        if options['active_only']:
            queryset = queryset.filter(is_active=True)
        
        clients = queryset.order_by('client_name')
        
        if options['format'] == 'json':
            client_data = []
            for client in clients:
                client_data.append({
                    'client_id': str(client.client_id),
                    'client_name': client.client_name,
                    'client_type': client.client_type,
                    'is_active': client.is_active,
                    'created_at': client.created_at.isoformat(),
                    'allowed_domains': client.allowed_domains,
                })
            self.stdout.write(json.dumps(client_data, indent=2))
        else:
            if not clients:
                self.stdout.write('No clients found.')
                return
            
            headers = ['Client ID', 'Name', 'Type', 'Status', 'Domains', 'Created']
            rows = []
            
            for client in clients:
                rows.append([
                    str(client.client_id)[:8] + '...',
                    client.client_name,
                    client.client_type,
                    'Active' if client.is_active else 'Inactive',
                    ', '.join(client.allowed_domains[:2]) + ('...' if len(client.allowed_domains) > 2 else ''),
                    client.created_at.strftime('%Y-%m-%d')
                ])
            
            self.stdout.write(tabulate(rows, headers=headers, tablefmt='grid'))

    def _show_client(self, client_id):
        """Show detailed information about a client."""
        try:
            client = RegisteredClient.objects.get(client_id=client_id)
        except RegisteredClient.DoesNotExist:
            raise CommandError(f'Client with ID {client_id} not found')
        
        self.stdout.write(f'Client Details for: {client.client_name}')
        self.stdout.write('=' * 50)
        self.stdout.write(f'Client ID: {client.client_id}')
        self.stdout.write(f'Client Name: {client.client_name}')
        self.stdout.write(f'Client Type: {client.client_type}')
        self.stdout.write(f'Status: {"Active" if client.is_active else "Inactive"}')
        self.stdout.write(f'Created: {client.created_at}')
        self.stdout.write(f'Updated: {client.updated_at}')
        self.stdout.write('')
        self.stdout.write('Allowed Domains:')
        if client.allowed_domains:
            for domain in client.allowed_domains:
                self.stdout.write(f'  - {domain}')
        else:
            self.stdout.write('  None specified')
        self.stdout.write('')
        self.stdout.write('Security Configuration:')
        self.stdout.write(f'  Rate Limit: {client.max_requests_per_minute} requests/minute')
        self.stdout.write(f'  Access Token Lifetime: {client.token_lifetime_access} minutes')
        self.stdout.write(f'  Refresh Token Lifetime: {client.token_lifetime_refresh} minutes')
        self.stdout.write(f'  Requires Device Fingerprint: {client.require_device_fingerprint}')
        self.stdout.write(f'  Allows Social Login: {client.allow_social_login}')
        self.stdout.write(f'  Requires TOTP: {client.require_totp}')
        self.stdout.write(f'  Enhanced Monitoring: {client.enhanced_monitoring}')

    def _activate_client(self, client_id):
        """Activate a client."""
        try:
            client = RegisteredClient.objects.get(client_id=client_id)
            client.is_active = True
            client.save()
            self.stdout.write(
                self.style.SUCCESS(f'Successfully activated client: {client.client_name}')
            )
        except RegisteredClient.DoesNotExist:
            raise CommandError(f'Client with ID {client_id} not found')

    def _deactivate_client(self, client_id):
        """Deactivate a client."""
        try:
            client = RegisteredClient.objects.get(client_id=client_id)
            client.is_active = False
            client.save()
            self.stdout.write(
                self.style.SUCCESS(f'Successfully deactivated client: {client.client_name}')
            )
        except RegisteredClient.DoesNotExist:
            raise CommandError(f'Client with ID {client_id} not found')

    def _rotate_credentials(self, client_id, output_format):
        """Rotate client credentials."""
        try:
            client = RegisteredClient.objects.get(client_id=client_id)
            
            # Generate new credentials
            new_credentials = ClientCredentialManager.rotate_client_credentials_safe(
                client_id, client.signing_key
            )
            
            # Update client with new credentials
            client.api_key_hash = new_credentials['api_key_hash']
            client.signing_key = new_credentials['signing_key']
            client.save()
            
            if output_format == 'json':
                output = {
                    'client_id': str(client.client_id),
                    'new_credentials': {
                        'api_key': new_credentials['api_key'],
                        'signing_key': new_credentials['signing_key'],
                        'public_key': new_credentials['public_key']
                    }
                }
                if 'old_signing_key' in new_credentials:
                    output['transition_period'] = {
                        'old_signing_key': new_credentials['old_signing_key'],
                        'old_public_key': new_credentials['old_public_key']
                    }
                self.stdout.write(json.dumps(output, indent=2))
            else:
                self.stdout.write(
                    self.style.SUCCESS(f'Successfully rotated credentials for: {client.client_name}')
                )
                self.stdout.write('')
                self.stdout.write('New Credentials:')
                self.stdout.write(f'  API Key: {new_credentials["api_key"]}')
                self.stdout.write('')
                self.stdout.write('New JWT Signing Key:')
                self.stdout.write(new_credentials['signing_key'])
                
        except RegisteredClient.DoesNotExist:
            raise CommandError(f'Client with ID {client_id} not found')

    def _update_client(self, options):
        """Update client configuration."""
        client_id = options['client_id']
        
        try:
            client = RegisteredClient.objects.get(client_id=client_id)
            
            updated_fields = []
            
            if options['name']:
                client.client_name = options['name']
                updated_fields.append('name')
            
            if options['domains'] is not None:
                client.allowed_domains = options['domains']
                updated_fields.append('domains')
            
            if options['rate_limit']:
                client.max_requests_per_minute = options['rate_limit']
                updated_fields.append('rate_limit')
            
            if updated_fields:
                client.save()
                self.stdout.write(
                    self.style.SUCCESS(
                        f'Successfully updated {", ".join(updated_fields)} for client: {client.client_name}'
                    )
                )
            else:
                self.stdout.write('No updates specified.')
                
        except RegisteredClient.DoesNotExist:
            raise CommandError(f'Client with ID {client_id} not found')

    def _delete_client(self, client_id, force):
        """Delete a client."""
        try:
            client = RegisteredClient.objects.get(client_id=client_id)
            
            if not force:
                confirm = input(f'Are you sure you want to delete client "{client.client_name}"? (y/N): ')
                if confirm.lower() != 'y':
                    self.stdout.write('Deletion cancelled.')
                    return
            
            client_name = client.client_name
            client.delete()
            
            self.stdout.write(
                self.style.SUCCESS(f'Successfully deleted client: {client_name}')
            )
            
        except RegisteredClient.DoesNotExist:
            raise CommandError(f'Client with ID {client_id} not found')
