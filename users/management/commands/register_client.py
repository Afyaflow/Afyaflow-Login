from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from users.models import RegisteredClient
from users.client_utils import ClientCredentialManager
from users.client_security import ClientSecurityPolicy
import json


class Command(BaseCommand):
    help = 'Register a new client application with the authentication service'

    def add_arguments(self, parser):
        parser.add_argument(
            'client_name',
            type=str,
            help='Name of the client application'
        )
        parser.add_argument(
            'client_type',
            type=str,
            choices=['PATIENT_WEB', 'PATIENT_MOBILE', 'PROVIDER_WEB', 'PROVIDER_MOBILE', 'ADMIN_WEB'],
            help='Type of client application'
        )
        parser.add_argument(
            '--domains',
            type=str,
            nargs='*',
            default=[],
            help='Allowed domains for this client (space-separated)'
        )
        parser.add_argument(
            '--inactive',
            action='store_true',
            help='Create client in inactive state'
        )
        parser.add_argument(
            '--custom-policy',
            type=str,
            help='JSON string with custom security policy overrides'
        )
        parser.add_argument(
            '--output-format',
            choices=['json', 'text'],
            default='text',
            help='Output format for credentials'
        )

    def handle(self, *args, **options):
        client_name = options['client_name']
        client_type = options['client_type']
        allowed_domains = options['domains']
        is_active = not options['inactive']
        custom_policy = options['custom_policy']
        output_format = options['output_format']

        try:
            with transaction.atomic():
                # Check if client with same name already exists
                if RegisteredClient.objects.filter(client_name=client_name).exists():
                    raise CommandError(f'Client with name "{client_name}" already exists')

                # Generate credentials
                credentials = ClientCredentialManager.create_client_credentials(
                    client_name, client_type
                )

                # Get default security policy
                default_policy = ClientSecurityPolicy.DEFAULT_POLICIES.get(client_type, {})
                
                # Apply custom policy overrides if provided
                if custom_policy:
                    try:
                        policy_overrides = json.loads(custom_policy)
                        default_policy.update(policy_overrides)
                    except json.JSONDecodeError:
                        raise CommandError('Invalid JSON in custom policy')

                # Create the client
                client = RegisteredClient.objects.create(
                    client_name=client_name,
                    client_type=client_type,
                    allowed_domains=allowed_domains,
                    api_key_hash=credentials['api_key_hash'],
                    signing_key=credentials['signing_key'],
                    is_active=is_active,
                    # Security policy fields
                    max_requests_per_minute=default_policy.get('max_requests_per_minute', 60),
                    token_lifetime_access=default_policy.get('token_lifetime_access', 60),
                    token_lifetime_refresh=default_policy.get('token_lifetime_refresh', 10080),
                    require_device_fingerprint=default_policy.get('require_device_fingerprint', False),
                    allow_social_login=default_policy.get('allow_social_login', True),
                    require_totp=default_policy.get('require_totp', False),
                    enhanced_monitoring=default_policy.get('enhanced_monitoring', False),
                )

                # Output credentials
                if output_format == 'json':
                    self._output_json(client, credentials)
                else:
                    self._output_text(client, credentials)

        except Exception as e:
            raise CommandError(f'Failed to register client: {str(e)}')

    def _output_text(self, client, credentials):
        """Output credentials in human-readable text format."""
        self.stdout.write(
            self.style.SUCCESS(f'Successfully registered client: {client.client_name}')
        )
        self.stdout.write('')
        self.stdout.write('Client Details:')
        self.stdout.write(f'  Client ID: {client.client_id}')
        self.stdout.write(f'  Client Name: {client.client_name}')
        self.stdout.write(f'  Client Type: {client.client_type}')
        self.stdout.write(f'  Status: {"Active" if client.is_active else "Inactive"}')
        self.stdout.write(f'  Allowed Domains: {", ".join(client.allowed_domains) if client.allowed_domains else "None"}')
        self.stdout.write('')
        self.stdout.write('Security Configuration:')
        self.stdout.write(f'  Rate Limit: {client.max_requests_per_minute} requests/minute')
        self.stdout.write(f'  Access Token Lifetime: {client.token_lifetime_access} minutes')
        self.stdout.write(f'  Refresh Token Lifetime: {client.token_lifetime_refresh} minutes')
        self.stdout.write(f'  Requires Device Fingerprint: {client.require_device_fingerprint}')
        self.stdout.write(f'  Allows Social Login: {client.allow_social_login}')
        self.stdout.write(f'  Requires TOTP: {client.require_totp}')
        self.stdout.write(f'  Enhanced Monitoring: {client.enhanced_monitoring}')
        self.stdout.write('')
        self.stdout.write(self.style.WARNING('IMPORTANT: Store these credentials securely!'))
        self.stdout.write('')
        self.stdout.write('Client Credentials:')
        self.stdout.write(f'  API Key: {credentials["api_key"]}')
        self.stdout.write('')
        self.stdout.write('JWT Signing Key:')
        self.stdout.write(credentials['signing_key'])
        self.stdout.write('')
        self.stdout.write('JWT Public Key (for verification):')
        self.stdout.write(credentials['public_key'])

    def _output_json(self, client, credentials):
        """Output credentials in JSON format."""
        output = {
            'client': {
                'client_id': str(client.client_id),
                'client_name': client.client_name,
                'client_type': client.client_type,
                'is_active': client.is_active,
                'allowed_domains': client.allowed_domains,
                'security_policy': {
                    'max_requests_per_minute': client.max_requests_per_minute,
                    'token_lifetime_access': client.token_lifetime_access,
                    'token_lifetime_refresh': client.token_lifetime_refresh,
                    'require_device_fingerprint': client.require_device_fingerprint,
                    'allow_social_login': client.allow_social_login,
                    'require_totp': client.require_totp,
                    'enhanced_monitoring': client.enhanced_monitoring,
                }
            },
            'credentials': {
                'api_key': credentials['api_key'],
                'signing_key': credentials['signing_key'],
                'public_key': credentials['public_key']
            }
        }
        
        self.stdout.write(json.dumps(output, indent=2))
