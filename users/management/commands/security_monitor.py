from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from users.models import RegisteredClient
from users.security_monitoring import SecurityMonitoringManager
import json
from tabulate import tabulate


class Command(BaseCommand):
    help = 'Monitor client security events and generate reports'

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(dest='action', help='Available actions')
        
        # Global summary
        summary_parser = subparsers.add_parser('summary', help='Show global security summary')
        summary_parser.add_argument(
            '--hours',
            type=int,
            default=24,
            help='Time period in hours (default: 24)'
        )
        summary_parser.add_argument(
            '--format',
            choices=['table', 'json'],
            default='table',
            help='Output format'
        )
        
        # Client-specific summary
        client_parser = subparsers.add_parser('client', help='Show client-specific security summary')
        client_parser.add_argument('client_id', help='Client ID to show summary for')
        client_parser.add_argument(
            '--hours',
            type=int,
            default=24,
            help='Time period in hours (default: 24)'
        )
        client_parser.add_argument(
            '--format',
            choices=['table', 'json'],
            default='table',
            help='Output format'
        )
        
        # Security alerts
        alerts_parser = subparsers.add_parser('alerts', help='Show security alerts')
        alerts_parser.add_argument(
            '--severity',
            choices=['low', 'medium', 'high', 'critical'],
            help='Filter by severity level'
        )
        alerts_parser.add_argument(
            '--hours',
            type=int,
            default=24,
            help='Time period in hours (default: 24)'
        )
        alerts_parser.add_argument(
            '--format',
            choices=['table', 'json'],
            default='table',
            help='Output format'
        )
        
        # Real-time monitoring
        monitor_parser = subparsers.add_parser('monitor', help='Start real-time monitoring')
        monitor_parser.add_argument(
            '--interval',
            type=int,
            default=30,
            help='Refresh interval in seconds (default: 30)'
        )

    def handle(self, *args, **options):
        action = options['action']
        
        if not action:
            self.print_help('security_monitor', '')
            return
        
        try:
            if action == 'summary':
                self._show_global_summary(options)
            elif action == 'client':
                self._show_client_summary(options)
            elif action == 'alerts':
                self._show_security_alerts(options)
            elif action == 'monitor':
                self._start_real_time_monitoring(options)
        except Exception as e:
            raise CommandError(f'Security monitoring failed: {str(e)}')

    def _show_global_summary(self, options):
        """Show global security summary."""
        hours = options['hours']
        output_format = options['format']
        
        summary = SecurityMonitoringManager.get_global_security_summary(hours)
        
        if output_format == 'json':
            self.stdout.write(json.dumps(summary, indent=2))
        else:
            self._output_global_summary_table(summary)

    def _show_client_summary(self, options):
        """Show client-specific security summary."""
        client_id = options['client_id']
        hours = options['hours']
        output_format = options['format']
        
        try:
            client = RegisteredClient.objects.get(client_id=client_id)
        except RegisteredClient.DoesNotExist:
            raise CommandError(f'Client with ID {client_id} not found')
        
        monitor = SecurityMonitoringManager.get_monitor_for_client(client)
        summary = monitor.get_security_summary(hours)
        
        if output_format == 'json':
            self.stdout.write(json.dumps(summary, indent=2))
        else:
            self._output_client_summary_table(summary)

    def _show_security_alerts(self, options):
        """Show security alerts."""
        severity = options['severity']
        hours = options['hours']
        output_format = options['format']
        
        alerts = SecurityMonitoringManager.get_security_alerts(severity, hours)
        
        if output_format == 'json':
            self.stdout.write(json.dumps(alerts, indent=2))
        else:
            self._output_alerts_table(alerts)

    def _start_real_time_monitoring(self, options):
        """Start real-time monitoring (simplified version)."""
        interval = options['interval']
        
        self.stdout.write(f'Starting real-time monitoring (refresh every {interval}s)')
        self.stdout.write('Press Ctrl+C to stop')
        
        try:
            import time
            while True:
                # Clear screen (simple version)
                self.stdout.write('\n' * 50)
                self.stdout.write('=== REAL-TIME SECURITY MONITORING ===')
                self.stdout.write(f'Last updated: {timezone.now().strftime("%Y-%m-%d %H:%M:%S")}')
                self.stdout.write('')
                
                # Show global summary
                summary = SecurityMonitoringManager.get_global_security_summary(1)  # Last hour
                self._output_global_summary_table(summary)
                
                # Show recent alerts
                alerts = SecurityMonitoringManager.get_security_alerts(hours=1)
                if alerts:
                    self.stdout.write('')
                    self.stdout.write('Recent Alerts (Last Hour):')
                    self._output_alerts_table(alerts[:5])  # Show only last 5
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            self.stdout.write('\nMonitoring stopped.')

    def _output_global_summary_table(self, summary):
        """Output global summary in table format."""
        self.stdout.write(f'Global Security Summary (Last {summary["time_period_hours"]} hours)')
        self.stdout.write('=' * 60)
        
        global_stats = summary['global_stats']
        
        # Global statistics table
        global_data = [
            ['Total Clients', summary['total_clients']],
            ['Total Attempts', global_stats['total_attempts']],
            ['Successful Attempts', global_stats['successful_attempts']],
            ['Failed Attempts', global_stats['failed_attempts']],
            ['Success Rate', f"{global_stats['success_rate']:.1f}%"],
            ['Total Security Events', global_stats['total_events']],
            ['Total Alerts', global_stats['total_alerts']]
        ]
        
        self.stdout.write(tabulate(global_data, headers=['Metric', 'Value'], tablefmt='grid'))
        
        # Client breakdown
        if summary['client_summaries']:
            self.stdout.write('')
            self.stdout.write('Client Breakdown:')
            
            client_data = []
            for client_summary in summary['client_summaries']:
                auth_summary = client_summary['authentication_summary']
                security_events = client_summary['security_events']
                
                client_data.append([
                    client_summary['client_name'][:20],
                    client_summary['client_id'][:8] + '...',
                    auth_summary['total_attempts'],
                    auth_summary['failed_attempts'],
                    f"{auth_summary['success_rate']:.1f}%",
                    security_events['total_events'],
                    len(client_summary['alerts'])
                ])
            
            headers = ['Client Name', 'Client ID', 'Attempts', 'Failures', 'Success Rate', 'Events', 'Alerts']
            self.stdout.write(tabulate(client_data, headers=headers, tablefmt='grid'))

    def _output_client_summary_table(self, summary):
        """Output client summary in table format."""
        self.stdout.write(f'Security Summary for: {summary["client_name"]}')
        self.stdout.write(f'Client ID: {summary["client_id"]}')
        self.stdout.write(f'Time Period: Last {summary["time_period_hours"]} hours')
        self.stdout.write('=' * 60)
        
        auth_summary = summary['authentication_summary']
        security_events = summary['security_events']
        
        # Authentication statistics
        auth_data = [
            ['Total Attempts', auth_summary['total_attempts']],
            ['Successful Attempts', auth_summary['successful_attempts']],
            ['Failed Attempts', auth_summary['failed_attempts']],
            ['Success Rate', f"{auth_summary['success_rate']:.1f}%"],
            ['Unique IP Addresses', auth_summary['unique_ips']]
        ]
        
        self.stdout.write('Authentication Statistics:')
        self.stdout.write(tabulate(auth_data, headers=['Metric', 'Value'], tablefmt='grid'))
        
        # Security events
        if security_events['total_events'] > 0:
            self.stdout.write('')
            self.stdout.write('Security Events by Severity:')
            
            severity_data = []
            for severity, count in security_events['by_severity'].items():
                severity_data.append([severity.title(), count])
            
            self.stdout.write(tabulate(severity_data, headers=['Severity', 'Count'], tablefmt='grid'))
        
        # Recent alerts
        if summary['alerts']:
            self.stdout.write('')
            self.stdout.write('Recent Alerts:')
            self._output_alerts_table(summary['alerts'])

    def _output_alerts_table(self, alerts):
        """Output alerts in table format."""
        if not alerts:
            self.stdout.write('No alerts found.')
            return
        
        alert_data = []
        for alert in alerts:
            alert_data.append([
                alert['timestamp'][:19],  # Remove microseconds
                alert['severity'].title(),
                alert['event_type'].replace('_', ' ').title(),
                alert['client_name'][:20],
                alert['description'][:50] + ('...' if len(alert['description']) > 50 else '')
            ])
        
        headers = ['Timestamp', 'Severity', 'Event Type', 'Client', 'Description']
        self.stdout.write(tabulate(alert_data, headers=headers, tablefmt='grid'))
