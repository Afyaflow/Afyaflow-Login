"""
Service discovery and registry system for tracking active services and their capabilities.
"""

import logging
import time
import threading
from typing import Dict, List, Set, Optional, Any
from datetime import datetime, timedelta
from django.core.cache import cache
from django.utils import timezone
from django.db import models

from .models import ServiceAccount

logger = logging.getLogger(__name__)


class ServiceRegistry:
    """
    Service registry for tracking active services, their health, and capabilities.
    """
    
    # Cache keys
    CACHE_KEY_ACTIVE_SERVICES = 'service_registry_active'
    CACHE_KEY_SERVICE_HEALTH = 'service_registry_health'
    CACHE_KEY_SERVICE_CAPABILITIES = 'service_registry_capabilities'
    
    # Default timeouts
    DEFAULT_HEARTBEAT_TIMEOUT = 300  # 5 minutes
    DEFAULT_CLEANUP_INTERVAL = 60    # 1 minute
    
    def __init__(self):
        self._cleanup_thread = None
        self._stop_event = threading.Event()
        self._start_cleanup_worker()
    
    def _start_cleanup_worker(self):
        """Start the cleanup worker thread."""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            return
        
        self._stop_event.clear()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_worker,
            daemon=True,
            name="ServiceRegistryCleanup"
        )
        self._cleanup_thread.start()
        logger.info("Started service registry cleanup worker")
    
    def _cleanup_worker(self):
        """Worker thread for cleaning up stale service registrations."""
        while not self._stop_event.is_set():
            try:
                self.cleanup_stale_services()
            except Exception as e:
                logger.error(f"Error in service registry cleanup: {str(e)}")
            
            # Wait for next cleanup or stop signal
            self._stop_event.wait(self.DEFAULT_CLEANUP_INTERVAL)
    
    def register_service(self, service_id: str, capabilities: Dict[str, Any] = None,
                        health_endpoint: str = None, metadata: Dict[str, Any] = None) -> bool:
        """
        Register a service in the registry.
        
        Args:
            service_id (str): Unique service identifier
            capabilities (dict, optional): Service capabilities and features
            health_endpoint (str, optional): Health check endpoint URL
            metadata (dict, optional): Additional service metadata
            
        Returns:
            bool: True if registration was successful
        """
        try:
            # Verify service account exists
            try:
                service_account = ServiceAccount.objects.get(
                    service_id=service_id,
                    is_active=True
                )
            except ServiceAccount.DoesNotExist:
                logger.warning(f"Attempted to register unknown service: {service_id}")
                return False
            
            now = timezone.now()
            
            # Service registration data
            service_data = {
                'service_id': service_id,
                'service_type': service_account.service_type,
                'permissions': service_account.permissions,
                'registered_at': now.isoformat(),
                'last_heartbeat': now.isoformat(),
                'health_endpoint': health_endpoint,
                'capabilities': capabilities or {},
                'metadata': metadata or {},
                'status': 'active'
            }
            
            # Update active services registry
            active_services = self.get_active_services()
            active_services[service_id] = service_data
            
            cache.set(
                self.CACHE_KEY_ACTIVE_SERVICES,
                active_services,
                timeout=self.DEFAULT_HEARTBEAT_TIMEOUT * 2
            )
            
            logger.info(f"Registered service: {service_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register service {service_id}: {str(e)}")
            return False
    
    def unregister_service(self, service_id: str) -> bool:
        """
        Unregister a service from the registry.
        
        Args:
            service_id (str): Service identifier to unregister
            
        Returns:
            bool: True if unregistration was successful
        """
        try:
            active_services = self.get_active_services()
            
            if service_id in active_services:
                del active_services[service_id]
                cache.set(
                    self.CACHE_KEY_ACTIVE_SERVICES,
                    active_services,
                    timeout=self.DEFAULT_HEARTBEAT_TIMEOUT * 2
                )
                
                # Remove health data
                health_data = self.get_service_health_data()
                if service_id in health_data:
                    del health_data[service_id]
                    cache.set(
                        self.CACHE_KEY_SERVICE_HEALTH,
                        health_data,
                        timeout=self.DEFAULT_HEARTBEAT_TIMEOUT * 2
                    )
                
                logger.info(f"Unregistered service: {service_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to unregister service {service_id}: {str(e)}")
            return False
    
    def heartbeat(self, service_id: str, health_status: Dict[str, Any] = None) -> bool:
        """
        Record a heartbeat from a service.
        
        Args:
            service_id (str): Service identifier
            health_status (dict, optional): Current health status information
            
        Returns:
            bool: True if heartbeat was recorded
        """
        try:
            active_services = self.get_active_services()
            
            if service_id not in active_services:
                logger.warning(f"Heartbeat from unregistered service: {service_id}")
                return False
            
            now = timezone.now()
            
            # Update last heartbeat
            active_services[service_id]['last_heartbeat'] = now.isoformat()
            active_services[service_id]['status'] = 'active'
            
            cache.set(
                self.CACHE_KEY_ACTIVE_SERVICES,
                active_services,
                timeout=self.DEFAULT_HEARTBEAT_TIMEOUT * 2
            )
            
            # Update health data if provided
            if health_status:
                health_data = self.get_service_health_data()
                health_data[service_id] = {
                    'last_check': now.isoformat(),
                    'status': health_status,
                    'healthy': health_status.get('healthy', True)
                }
                
                cache.set(
                    self.CACHE_KEY_SERVICE_HEALTH,
                    health_data,
                    timeout=self.DEFAULT_HEARTBEAT_TIMEOUT * 2
                )
            
            logger.debug(f"Recorded heartbeat for service: {service_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to record heartbeat for {service_id}: {str(e)}")
            return False
    
    def get_active_services(self) -> Dict[str, Dict[str, Any]]:
        """Get all currently active services."""
        return cache.get(self.CACHE_KEY_ACTIVE_SERVICES, {})
    
    def get_service_health_data(self) -> Dict[str, Dict[str, Any]]:
        """Get health data for all services."""
        return cache.get(self.CACHE_KEY_SERVICE_HEALTH, {})
    
    def get_service_info(self, service_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a specific service.
        
        Args:
            service_id (str): Service identifier
            
        Returns:
            dict: Service information or None if not found
        """
        active_services = self.get_active_services()
        service_info = active_services.get(service_id)
        
        if service_info:
            # Add health information
            health_data = self.get_service_health_data()
            service_info['health'] = health_data.get(service_id, {})
        
        return service_info
    
    def discover_services(self, service_type: str = None, 
                         capabilities: List[str] = None) -> List[Dict[str, Any]]:
        """
        Discover services based on criteria.
        
        Args:
            service_type (str, optional): Filter by service type
            capabilities (list, optional): Required capabilities
            
        Returns:
            list: List of matching services
        """
        active_services = self.get_active_services()
        matching_services = []
        
        for service_id, service_data in active_services.items():
            # Check service type filter
            if service_type and service_data.get('service_type') != service_type:
                continue
            
            # Check capabilities filter
            if capabilities:
                service_capabilities = service_data.get('capabilities', {})
                if not all(cap in service_capabilities for cap in capabilities):
                    continue
            
            # Check if service is healthy (recent heartbeat)
            last_heartbeat = service_data.get('last_heartbeat')
            if last_heartbeat:
                heartbeat_time = datetime.fromisoformat(last_heartbeat.replace('Z', '+00:00'))
                if timezone.now() - heartbeat_time > timedelta(seconds=self.DEFAULT_HEARTBEAT_TIMEOUT):
                    continue
            
            matching_services.append(service_data)
        
        return matching_services
    
    def cleanup_stale_services(self):
        """Remove services that haven't sent heartbeats recently."""
        try:
            active_services = self.get_active_services()
            stale_services = []
            
            cutoff_time = timezone.now() - timedelta(seconds=self.DEFAULT_HEARTBEAT_TIMEOUT)
            
            for service_id, service_data in active_services.items():
                last_heartbeat = service_data.get('last_heartbeat')
                if last_heartbeat:
                    heartbeat_time = datetime.fromisoformat(last_heartbeat.replace('Z', '+00:00'))
                    if heartbeat_time < cutoff_time:
                        stale_services.append(service_id)
            
            # Remove stale services
            for service_id in stale_services:
                self.unregister_service(service_id)
                logger.info(f"Removed stale service: {service_id}")
            
            if stale_services:
                logger.info(f"Cleaned up {len(stale_services)} stale services")
                
        except Exception as e:
            logger.error(f"Error during service cleanup: {str(e)}")
    
    def get_registry_stats(self) -> Dict[str, Any]:
        """Get registry statistics."""
        active_services = self.get_active_services()
        health_data = self.get_service_health_data()
        
        # Count services by type
        service_types = {}
        healthy_count = 0
        
        for service_id, service_data in active_services.items():
            service_type = service_data.get('service_type', 'unknown')
            service_types[service_type] = service_types.get(service_type, 0) + 1
            
            # Check health
            health_info = health_data.get(service_id, {})
            if health_info.get('healthy', True):
                healthy_count += 1
        
        return {
            'total_services': len(active_services),
            'healthy_services': healthy_count,
            'service_types': service_types,
            'registry_uptime': time.time(),  # Simplified uptime
            'cleanup_thread_alive': self._cleanup_thread and self._cleanup_thread.is_alive()
        }
    
    def stop(self):
        """Stop the service registry."""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._stop_event.set()
            self._cleanup_thread.join(timeout=5)
            logger.info("Stopped service registry")


# Global service registry instance
_service_registry = None


def get_service_registry() -> ServiceRegistry:
    """Get the global service registry instance."""
    global _service_registry
    if _service_registry is None:
        _service_registry = ServiceRegistry()
    return _service_registry
