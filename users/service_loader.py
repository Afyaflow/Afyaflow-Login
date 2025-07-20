"""
Dynamic service account loader with hot-reload capabilities.
Manages service account configuration from environment variables with real-time updates.
"""

import os
import logging
import threading
import time
from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime, timedelta
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.core.cache import cache

from .models import ServiceAccount

logger = logging.getLogger(__name__)


class ServiceAccountLoader:
    """
    Dynamic loader for service accounts with hot-reload capabilities.
    Monitors environment variables and updates service accounts in real-time.
    """
    
    # Cache keys
    CACHE_KEY_LAST_LOAD = 'service_accounts_last_load'
    CACHE_KEY_CONFIG_HASH = 'service_accounts_config_hash'
    CACHE_KEY_ACTIVE_SERVICES = 'active_service_accounts'
    
    # Reload interval (in seconds)
    DEFAULT_RELOAD_INTERVAL = 300  # 5 minutes
    
    def __init__(self, auto_reload: bool = True, reload_interval: int = None):
        self.auto_reload = auto_reload
        self.reload_interval = reload_interval or self.DEFAULT_RELOAD_INTERVAL
        self._stop_event = threading.Event()
        self._reload_thread = None
        self._last_config_hash = None
        
        if auto_reload:
            self.start_auto_reload()
    
    def start_auto_reload(self):
        """Start automatic reloading of service accounts."""
        if self._reload_thread and self._reload_thread.is_alive():
            logger.warning("Auto-reload already running")
            return
        
        self._stop_event.clear()
        self._reload_thread = threading.Thread(
            target=self._auto_reload_worker,
            daemon=True,
            name="ServiceAccountLoader"
        )
        self._reload_thread.start()
        logger.info(f"Started service account auto-reload (interval: {self.reload_interval}s)")
    
    def stop_auto_reload(self):
        """Stop automatic reloading."""
        if self._reload_thread and self._reload_thread.is_alive():
            self._stop_event.set()
            self._reload_thread.join(timeout=5)
            logger.info("Stopped service account auto-reload")
    
    def _auto_reload_worker(self):
        """Worker thread for automatic reloading."""
        while not self._stop_event.is_set():
            try:
                self.reload_if_changed()
            except Exception as e:
                logger.error(f"Error in service account auto-reload: {str(e)}")
            
            # Wait for next reload or stop signal
            self._stop_event.wait(self.reload_interval)
    
    def reload_if_changed(self) -> bool:
        """
        Reload service accounts if configuration has changed.
        
        Returns:
            bool: True if reload was performed
        """
        current_hash = self._get_config_hash()
        
        if current_hash != self._last_config_hash:
            logger.info("Service account configuration changed, reloading...")
            result = self.load_service_accounts()
            self._last_config_hash = current_hash
            cache.set(self.CACHE_KEY_CONFIG_HASH, current_hash, timeout=3600)
            return result['success']
        
        return False
    
    def _get_config_hash(self) -> str:
        """Get hash of current service account configuration."""
        import hashlib
        
        # Get all service account related environment variables
        service_vars = []
        
        # Get service account IDs
        service_ids = self._get_service_ids_from_env()
        service_vars.append(f"SERVICE_ACCOUNT_IDS={','.join(sorted(service_ids))}")
        
        # Get configuration for each service
        for service_id in sorted(service_ids):
            normalized_id = self._normalize_service_id(service_id)
            
            service_type = os.getenv(f'SERVICE_ACCOUNT_{normalized_id}_TYPE', '')
            permissions = os.getenv(f'SERVICE_ACCOUNT_{normalized_id}_PERMISSIONS', '')
            
            service_vars.append(f"{normalized_id}_TYPE={service_type}")
            service_vars.append(f"{normalized_id}_PERMISSIONS={permissions}")
        
        # Create hash of all configuration
        config_string = '|'.join(service_vars)
        return hashlib.md5(config_string.encode()).hexdigest()
    
    def _get_service_ids_from_env(self) -> List[str]:
        """Get service account IDs from environment variables."""
        service_ids_str = os.getenv('SERVICE_ACCOUNT_IDS', '')
        if not service_ids_str:
            # Try to get from Django settings as fallback
            service_ids_str = ','.join(getattr(settings, 'SERVICE_ACCOUNT_IDS', []))
        
        return [sid.strip() for sid in service_ids_str.split(',') if sid.strip()]
    
    def _normalize_service_id(self, service_id: str) -> str:
        """Normalize service ID for environment variable names."""
        return service_id.upper().replace('-', '_').replace('.', '_')
    
    def load_service_accounts(self, force_update: bool = False) -> Dict[str, any]:
        """
        Load service accounts from environment variables.
        
        Args:
            force_update (bool): Force update existing service accounts
            
        Returns:
            dict: Load result with statistics
        """
        start_time = time.time()
        result = {
            'success': False,
            'created_count': 0,
            'updated_count': 0,
            'deactivated_count': 0,
            'errors': [],
            'load_time': 0
        }
        
        try:
            with transaction.atomic():
                service_ids = self._get_service_ids_from_env()
                
                if not service_ids:
                    logger.warning("No service account IDs found in environment")
                    result['success'] = True
                    return result
                
                logger.info(f"Loading {len(service_ids)} service accounts from environment")
                
                # Track which services are in the environment
                env_service_ids = set(service_ids)
                
                # Process each service account
                for service_id in service_ids:
                    try:
                        created, updated = self._load_single_service_account(
                            service_id, force_update
                        )
                        if created:
                            result['created_count'] += 1
                        elif updated:
                            result['updated_count'] += 1
                            
                    except Exception as e:
                        error_msg = f"Failed to load service account {service_id}: {str(e)}"
                        result['errors'].append(error_msg)
                        logger.error(error_msg)
                
                # Deactivate services not in environment (if they exist)
                deactivated = self._deactivate_missing_services(env_service_ids)
                result['deactivated_count'] = deactivated
                
                # Update cache
                cache.set(self.CACHE_KEY_LAST_LOAD, timezone.now(), timeout=3600)
                cache.set(self.CACHE_KEY_ACTIVE_SERVICES, list(env_service_ids), timeout=3600)
                
                result['success'] = True
                result['load_time'] = time.time() - start_time
                
                logger.info(
                    f"Service account load completed: "
                    f"created={result['created_count']}, "
                    f"updated={result['updated_count']}, "
                    f"deactivated={result['deactivated_count']}, "
                    f"errors={len(result['errors'])}, "
                    f"time={result['load_time']:.2f}s"
                )
                
        except Exception as e:
            result['errors'].append(f"Transaction failed: {str(e)}")
            logger.error(f"Service account loading failed: {str(e)}")
        
        return result
    
    def _load_single_service_account(self, service_id: str, force_update: bool) -> Tuple[bool, bool]:
        """
        Load a single service account from environment.
        
        Returns:
            tuple: (created, updated) booleans
        """
        normalized_id = self._normalize_service_id(service_id)
        
        # Get configuration from environment
        service_type = os.getenv(f'SERVICE_ACCOUNT_{normalized_id}_TYPE')
        permissions_str = os.getenv(f'SERVICE_ACCOUNT_{normalized_id}_PERMISSIONS', '')
        
        if not service_type:
            raise ValueError(f"Missing SERVICE_ACCOUNT_{normalized_id}_TYPE")
        
        # Parse permissions
        permissions = []
        if permissions_str:
            permissions = [p.strip() for p in permissions_str.split(',') if p.strip()]
        
        # Create or update service account
        service_account, created = ServiceAccount.objects.get_or_create(
            service_id=service_id,
            defaults={
                'service_type': service_type,
                'permissions': permissions,
                'is_active': True
            }
        )
        
        updated = False
        if not created and force_update:
            # Update existing service account
            if (service_account.service_type != service_type or 
                service_account.permissions != permissions or 
                not service_account.is_active):
                
                service_account.service_type = service_type
                service_account.permissions = permissions
                service_account.is_active = True
                service_account.save()
                updated = True
        
        return created, updated
    
    def _deactivate_missing_services(self, env_service_ids: Set[str]) -> int:
        """
        Deactivate service accounts not present in environment.
        
        Args:
            env_service_ids (set): Set of service IDs from environment
            
        Returns:
            int: Number of deactivated services
        """
        # Find active services not in environment
        missing_services = ServiceAccount.objects.filter(
            is_active=True
        ).exclude(
            service_id__in=env_service_ids
        )
        
        deactivated_count = missing_services.count()
        if deactivated_count > 0:
            missing_services.update(is_active=False)
            logger.info(f"Deactivated {deactivated_count} service accounts not in environment")
        
        return deactivated_count
    
    def get_load_status(self) -> Dict[str, any]:
        """Get current load status and statistics."""
        last_load = cache.get(self.CACHE_KEY_LAST_LOAD)
        config_hash = cache.get(self.CACHE_KEY_CONFIG_HASH)
        active_services = cache.get(self.CACHE_KEY_ACTIVE_SERVICES, [])
        
        # Get database statistics
        total_services = ServiceAccount.objects.count()
        active_services_db = ServiceAccount.objects.filter(is_active=True).count()
        
        return {
            'auto_reload_enabled': self.auto_reload,
            'reload_interval': self.reload_interval,
            'last_load_time': last_load.isoformat() if last_load else None,
            'config_hash': config_hash,
            'active_services_env': len(active_services),
            'total_services_db': total_services,
            'active_services_db': active_services_db,
            'reload_thread_alive': self._reload_thread and self._reload_thread.is_alive(),
        }
    
    def validate_configuration(self) -> Dict[str, any]:
        """
        Validate current service account configuration.
        
        Returns:
            dict: Validation result with issues and recommendations
        """
        issues = []
        warnings = []
        
        service_ids = self._get_service_ids_from_env()
        
        if not service_ids:
            issues.append("No service account IDs configured in SERVICE_ACCOUNT_IDS")
        
        for service_id in service_ids:
            normalized_id = self._normalize_service_id(service_id)
            
            # Check required environment variables
            service_type = os.getenv(f'SERVICE_ACCOUNT_{normalized_id}_TYPE')
            if not service_type:
                issues.append(f"Missing SERVICE_ACCOUNT_{normalized_id}_TYPE")
            
            permissions_str = os.getenv(f'SERVICE_ACCOUNT_{normalized_id}_PERMISSIONS')
            if not permissions_str:
                warnings.append(f"No permissions configured for {service_id}")
            else:
                # Validate permission format
                permissions = [p.strip() for p in permissions_str.split(',') if p.strip()]
                for perm in permissions:
                    if ':' not in perm and perm != '*':
                        warnings.append(f"Permission '{perm}' for {service_id} should follow 'resource:action' format")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'warnings': warnings,
            'service_count': len(service_ids)
        }


# Global service account loader instance
_service_loader = None


def get_service_loader() -> ServiceAccountLoader:
    """Get the global service account loader instance."""
    global _service_loader
    if _service_loader is None:
        _service_loader = ServiceAccountLoader()
    return _service_loader


def reload_service_accounts(force_update: bool = False) -> Dict[str, any]:
    """Convenience function to reload service accounts."""
    loader = get_service_loader()
    return loader.load_service_accounts(force_update=force_update)


def validate_service_configuration() -> Dict[str, any]:
    """Convenience function to validate service configuration."""
    loader = get_service_loader()
    return loader.validate_configuration()


def get_service_load_status() -> Dict[str, any]:
    """Convenience function to get service load status."""
    loader = get_service_loader()
    return loader.get_load_status()
