import logging
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings
from datetime import timedelta
from typing import Dict, Any, List, Optional
from collections import defaultdict

from .models import RegisteredClient, AuthenticationAttempt, User, BlacklistedToken

logger = logging.getLogger(__name__)


class SecurityEvent:
    """
    Represents a security event for monitoring purposes.
    """
    
    SEVERITY_LOW = 'low'
    SEVERITY_MEDIUM = 'medium'
    SEVERITY_HIGH = 'high'
    SEVERITY_CRITICAL = 'critical'
    
    def __init__(self, event_type: str, severity: str, client: RegisteredClient, 
                 description: str, metadata: Dict[str, Any] = None):
        self.event_type = event_type
        self.severity = severity
        self.client = client
        self.description = description
        self.metadata = metadata or {}
        self.timestamp = timezone.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert security event to dictionary."""
        return {
            'event_type': self.event_type,
            'severity': self.severity,
            'client_id': str(self.client.client_id),
            'client_name': self.client.client_name,
            'client_type': self.client.client_type,
            'description': self.description,
            'metadata': self.metadata,
            'timestamp': self.timestamp.isoformat()
        }


class ClientSecurityMonitor:
    """
    Monitors security events and violations for client applications.
    """
    
    def __init__(self, client: RegisteredClient):
        self.client = client
        self.cache_prefix = f"security_monitor:{client.client_id}"
    
    def record_authentication_attempt(self, success: bool, ip_address: str, 
                                    user_agent: str, user: User = None, 
                                    failure_reason: str = None, 
                                    additional_context: Dict[str, Any] = None) -> SecurityEvent:
        """
        Record an authentication attempt and analyze for security threats.
        """
        # Create authentication attempt record
        attempt = AuthenticationAttempt.objects.create(
            email=user.email if user else None,
            attempt_type='client_auth',
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            failure_reason=failure_reason,
            user=user,
            client=self.client,
            client_type=self.client.client_type,
            security_context=additional_context or {}
        )
        
        # Analyze for security threats
        if not success:
            return self._analyze_failed_attempt(attempt)
        else:
            return self._analyze_successful_attempt(attempt)
    
    def _analyze_failed_attempt(self, attempt: AuthenticationAttempt) -> SecurityEvent:
        """
        Analyze failed authentication attempt for security threats.
        """
        # Check for brute force attacks
        recent_failures = self._get_recent_failed_attempts(attempt.ip_address, hours=1)
        
        if len(recent_failures) >= 5:  # 5 failures in 1 hour
            return self._create_security_event(
                'brute_force_detected',
                SecurityEvent.SEVERITY_HIGH,
                f"Brute force attack detected from IP {attempt.ip_address}",
                {
                    'ip_address': attempt.ip_address,
                    'failure_count': len(recent_failures),
                    'time_window': '1 hour',
                    'user_agent': attempt.user_agent
                }
            )
        elif len(recent_failures) >= 3:  # 3 failures in 1 hour
            return self._create_security_event(
                'suspicious_activity',
                SecurityEvent.SEVERITY_MEDIUM,
                f"Multiple failed attempts from IP {attempt.ip_address}",
                {
                    'ip_address': attempt.ip_address,
                    'failure_count': len(recent_failures),
                    'time_window': '1 hour'
                }
            )
        else:
            return self._create_security_event(
                'authentication_failure',
                SecurityEvent.SEVERITY_LOW,
                f"Authentication failure: {attempt.failure_reason}",
                {
                    'ip_address': attempt.ip_address,
                    'failure_reason': attempt.failure_reason
                }
            )
    
    def _analyze_successful_attempt(self, attempt: AuthenticationAttempt) -> SecurityEvent:
        """
        Analyze successful authentication attempt for anomalies.
        """
        if attempt.user:
            # Check for unusual login patterns
            user_recent_logins = AuthenticationAttempt.objects.filter(
                user=attempt.user,
                client=self.client,
                success=True,
                timestamp__gte=timezone.now() - timedelta(days=7)
            ).order_by('-timestamp')[:10]
            
            # Check for new IP address
            known_ips = set(login.ip_address for login in user_recent_logins[1:])  # Exclude current
            if attempt.ip_address not in known_ips and len(known_ips) > 0:
                return self._create_security_event(
                    'new_ip_login',
                    SecurityEvent.SEVERITY_MEDIUM,
                    f"User {attempt.user.email} logged in from new IP address",
                    {
                        'user_email': attempt.user.email,
                        'new_ip': attempt.ip_address,
                        'known_ips': list(known_ips)
                    }
                )
        
        return self._create_security_event(
            'successful_authentication',
            SecurityEvent.SEVERITY_LOW,
            "Successful authentication",
            {
                'ip_address': attempt.ip_address,
                'user_email': attempt.user.email if attempt.user else None
            }
        )
    
    def _get_recent_failed_attempts(self, ip_address: str, hours: int = 1) -> List[AuthenticationAttempt]:
        """
        Get recent failed attempts from an IP address.
        """
        since = timezone.now() - timedelta(hours=hours)
        return list(AuthenticationAttempt.objects.filter(
            client=self.client,
            ip_address=ip_address,
            success=False,
            timestamp__gte=since
        ).order_by('-timestamp'))
    
    def _create_security_event(self, event_type: str, severity: str, 
                             description: str, metadata: Dict[str, Any]) -> SecurityEvent:
        """
        Create and log a security event.
        """
        event = SecurityEvent(event_type, severity, self.client, description, metadata)
        
        # Log the event
        log_level = {
            SecurityEvent.SEVERITY_LOW: logging.INFO,
            SecurityEvent.SEVERITY_MEDIUM: logging.WARNING,
            SecurityEvent.SEVERITY_HIGH: logging.ERROR,
            SecurityEvent.SEVERITY_CRITICAL: logging.CRITICAL
        }.get(severity, logging.INFO)
        
        logger.log(log_level, f"Security Event [{severity.upper()}]: {description} (Client: {self.client.client_name})")
        
        # Store in cache for real-time monitoring
        self._cache_security_event(event)
        
        # Trigger alerts for high/critical events
        if severity in [SecurityEvent.SEVERITY_HIGH, SecurityEvent.SEVERITY_CRITICAL]:
            self._trigger_security_alert(event)
        
        return event
    
    def _cache_security_event(self, event: SecurityEvent):
        """
        Cache security event for real-time monitoring.
        """
        cache_key = f"{self.cache_prefix}:events"
        
        # Get existing events (last 100)
        events = cache.get(cache_key, [])
        
        # Add new event
        events.insert(0, event.to_dict())
        
        # Keep only last 100 events
        events = events[:100]
        
        # Cache for 24 hours
        cache.set(cache_key, events, 86400)
    
    def _trigger_security_alert(self, event: SecurityEvent):
        """
        Trigger security alert for high-severity events.
        """
        # In a real implementation, this would send notifications
        # via email, Slack, PagerDuty, etc.
        logger.critical(f"SECURITY ALERT: {event.description} (Client: {self.client.client_name})")
        
        # Store alert in cache for dashboard
        alert_key = f"{self.cache_prefix}:alerts"
        alerts = cache.get(alert_key, [])
        alerts.insert(0, event.to_dict())
        alerts = alerts[:50]  # Keep last 50 alerts
        cache.set(alert_key, alerts, 86400)
    
    def get_security_summary(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get security summary for the client.
        """
        since = timezone.now() - timedelta(hours=hours)
        
        # Get authentication attempts
        attempts = AuthenticationAttempt.objects.filter(
            client=self.client,
            timestamp__gte=since
        )
        
        total_attempts = attempts.count()
        successful_attempts = attempts.filter(success=True).count()
        failed_attempts = attempts.filter(success=False).count()
        
        # Get unique IPs
        unique_ips = attempts.values_list('ip_address', flat=True).distinct().count()
        
        # Get recent security events
        events = cache.get(f"{self.cache_prefix}:events", [])
        recent_events = [e for e in events if 
                        timezone.now() - timezone.fromisoformat(e['timestamp']) <= timedelta(hours=hours)]
        
        # Count events by severity
        event_counts = defaultdict(int)
        for event in recent_events:
            event_counts[event['severity']] += 1
        
        return {
            'client_id': str(self.client.client_id),
            'client_name': self.client.client_name,
            'time_period_hours': hours,
            'authentication_summary': {
                'total_attempts': total_attempts,
                'successful_attempts': successful_attempts,
                'failed_attempts': failed_attempts,
                'success_rate': (successful_attempts / total_attempts * 100) if total_attempts > 0 else 0,
                'unique_ips': unique_ips
            },
            'security_events': {
                'total_events': len(recent_events),
                'by_severity': dict(event_counts),
                'recent_events': recent_events[:10]  # Last 10 events
            },
            'alerts': cache.get(f"{self.cache_prefix}:alerts", [])[:5]  # Last 5 alerts
        }


class SecurityMonitoringManager:
    """
    Manager class for security monitoring operations across all clients.
    """
    
    @staticmethod
    def get_monitor_for_client(client: RegisteredClient) -> ClientSecurityMonitor:
        """
        Get security monitor for a specific client.
        """
        return ClientSecurityMonitor(client)
    
    @staticmethod
    def record_client_authentication(client: RegisteredClient, success: bool, 
                                   ip_address: str, user_agent: str, 
                                   user: User = None, failure_reason: str = None,
                                   additional_context: Dict[str, Any] = None) -> SecurityEvent:
        """
        Record authentication attempt for a client.
        """
        monitor = ClientSecurityMonitor(client)
        return monitor.record_authentication_attempt(
            success, ip_address, user_agent, user, failure_reason, additional_context
        )
    
    @staticmethod
    def get_global_security_summary(hours: int = 24) -> Dict[str, Any]:
        """
        Get global security summary across all clients.
        """
        since = timezone.now() - timedelta(hours=hours)
        
        # Get all active clients
        clients = RegisteredClient.objects.filter(is_active=True)
        
        global_summary = {
            'time_period_hours': hours,
            'total_clients': clients.count(),
            'client_summaries': [],
            'global_stats': {
                'total_attempts': 0,
                'successful_attempts': 0,
                'failed_attempts': 0,
                'total_events': 0,
                'total_alerts': 0
            }
        }
        
        for client in clients:
            monitor = ClientSecurityMonitor(client)
            client_summary = monitor.get_security_summary(hours)
            global_summary['client_summaries'].append(client_summary)
            
            # Aggregate global stats
            auth_summary = client_summary['authentication_summary']
            global_summary['global_stats']['total_attempts'] += auth_summary['total_attempts']
            global_summary['global_stats']['successful_attempts'] += auth_summary['successful_attempts']
            global_summary['global_stats']['failed_attempts'] += auth_summary['failed_attempts']
            global_summary['global_stats']['total_events'] += client_summary['security_events']['total_events']
            global_summary['global_stats']['total_alerts'] += len(client_summary['alerts'])
        
        # Calculate global success rate
        total_attempts = global_summary['global_stats']['total_attempts']
        successful_attempts = global_summary['global_stats']['successful_attempts']
        global_summary['global_stats']['success_rate'] = (
            (successful_attempts / total_attempts * 100) if total_attempts > 0 else 0
        )
        
        return global_summary
    
    @staticmethod
    def get_security_alerts(severity_filter: str = None, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Get security alerts across all clients.
        """
        all_alerts = []
        
        for client in RegisteredClient.objects.filter(is_active=True):
            cache_key = f"security_monitor:{client.client_id}:alerts"
            client_alerts = cache.get(cache_key, [])
            
            # Filter by time and severity
            for alert in client_alerts:
                alert_time = timezone.fromisoformat(alert['timestamp'])
                if timezone.now() - alert_time <= timedelta(hours=hours):
                    if not severity_filter or alert['severity'] == severity_filter:
                        all_alerts.append(alert)
        
        # Sort by timestamp (newest first)
        all_alerts.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return all_alerts
