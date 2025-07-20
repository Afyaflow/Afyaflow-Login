import re
import logging
from urllib.parse import urlparse
from typing import List, Optional, Dict, Any
from django.conf import settings

from .models import RegisteredClient

logger = logging.getLogger(__name__)


class DomainValidator:
    """
    Validates domains and origins against client-specific allowed domains.
    """
    
    def __init__(self, client: RegisteredClient):
        self.client = client
        self.allowed_domains = client.allowed_domains or []
    
    def validate_origin(self, origin: str) -> Dict[str, Any]:
        """
        Validate an origin against allowed domains.
        
        Args:
            origin (str): The origin to validate (e.g., "https://example.com")
            
        Returns:
            Dict with validation results
        """
        if not origin:
            return {
                'valid': not self.allowed_domains,  # Valid if no domains configured
                'reason': 'No origin provided',
                'domain': None
            }
        
        # Extract domain from origin
        domain = self._extract_domain_from_origin(origin)
        
        if not domain:
            return {
                'valid': False,
                'reason': 'Invalid origin format',
                'domain': None
            }
        
        # Check if domain is allowed
        is_allowed = self._is_domain_allowed(domain)
        
        result = {
            'valid': is_allowed,
            'domain': domain,
            'origin': origin,
            'client_id': str(self.client.client_id),
            'allowed_domains': self.allowed_domains
        }
        
        if is_allowed:
            result['reason'] = 'Domain is allowed'
            logger.debug(f"Domain validation passed for {domain} (client: {self.client.client_name})")
        else:
            result['reason'] = f'Domain {domain} is not in allowed domains list'
            logger.warning(f"Domain validation failed for {domain} (client: {self.client.client_name})")
        
        return result
    
    def validate_referer(self, referer: str) -> Dict[str, Any]:
        """
        Validate a referer URL against allowed domains.
        
        Args:
            referer (str): The referer URL to validate
            
        Returns:
            Dict with validation results
        """
        if not referer:
            return {
                'valid': not self.allowed_domains,  # Valid if no domains configured
                'reason': 'No referer provided',
                'domain': None
            }
        
        # Extract domain from referer
        domain = self._extract_domain_from_url(referer)
        
        if not domain:
            return {
                'valid': False,
                'reason': 'Invalid referer URL format',
                'domain': None
            }
        
        # Check if domain is allowed
        is_allowed = self._is_domain_allowed(domain)
        
        result = {
            'valid': is_allowed,
            'domain': domain,
            'referer': referer,
            'client_id': str(self.client.client_id),
            'allowed_domains': self.allowed_domains
        }
        
        if is_allowed:
            result['reason'] = 'Domain is allowed'
        else:
            result['reason'] = f'Domain {domain} is not in allowed domains list'
        
        return result
    
    def _extract_domain_from_origin(self, origin: str) -> Optional[str]:
        """
        Extract domain from an origin string.
        
        Args:
            origin (str): Origin string (e.g., "https://example.com")
            
        Returns:
            str or None: Extracted domain
        """
        try:
            # Parse the origin URL
            parsed = urlparse(origin)
            
            # Return the netloc (domain:port)
            return parsed.netloc.lower() if parsed.netloc else None
        except Exception as e:
            logger.error(f"Failed to parse origin {origin}: {e}")
            return None
    
    def _extract_domain_from_url(self, url: str) -> Optional[str]:
        """
        Extract domain from a full URL.
        
        Args:
            url (str): Full URL
            
        Returns:
            str or None: Extracted domain
        """
        try:
            # Parse the URL
            parsed = urlparse(url)
            
            # Return the netloc (domain:port)
            return parsed.netloc.lower() if parsed.netloc else None
        except Exception as e:
            logger.error(f"Failed to parse URL {url}: {e}")
            return None
    
    def _is_domain_allowed(self, domain: str) -> bool:
        """
        Check if a domain is in the allowed domains list.
        
        Args:
            domain (str): Domain to check
            
        Returns:
            bool: True if domain is allowed
        """
        if not self.allowed_domains:
            # If no domains are configured, allow all (for development)
            return True
        
        domain = domain.lower()
        
        # Check exact matches
        if domain in [d.lower() for d in self.allowed_domains]:
            return True
        
        # Check wildcard matches
        for allowed_domain in self.allowed_domains:
            if self._matches_wildcard_domain(domain, allowed_domain.lower()):
                return True
        
        return False
    
    def _matches_wildcard_domain(self, domain: str, pattern: str) -> bool:
        """
        Check if a domain matches a wildcard pattern.
        
        Args:
            domain (str): Domain to check
            pattern (str): Pattern with potential wildcards
            
        Returns:
            bool: True if domain matches pattern
        """
        # Convert wildcard pattern to regex
        # *.example.com -> ^.*\.example\.com$
        if pattern.startswith('*.'):
            # Wildcard subdomain pattern
            base_domain = pattern[2:]  # Remove *.
            regex_pattern = r'^.*\.' + re.escape(base_domain) + r'$'
            return bool(re.match(regex_pattern, domain))
        
        # Exact match (already handled above, but included for completeness)
        return domain == pattern
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """
        Get a summary of domain validation configuration.
        
        Returns:
            Dict with validation configuration summary
        """
        return {
            'client_id': str(self.client.client_id),
            'client_name': self.client.client_name,
            'client_type': self.client.client_type,
            'domain_validation_enabled': bool(self.allowed_domains),
            'allowed_domains_count': len(self.allowed_domains),
            'allowed_domains': self.allowed_domains,
            'wildcard_domains': [d for d in self.allowed_domains if d.startswith('*.')],
            'exact_domains': [d for d in self.allowed_domains if not d.startswith('*.')]
        }


class DomainValidationManager:
    """
    Manager class for domain validation operations.
    """
    
    @staticmethod
    def validate_request_origin(client: RegisteredClient, origin: str) -> Dict[str, Any]:
        """
        Validate request origin for a client.
        
        Args:
            client (RegisteredClient): The client
            origin (str): Origin to validate
            
        Returns:
            Dict with validation results
        """
        validator = DomainValidator(client)
        return validator.validate_origin(origin)
    
    @staticmethod
    def validate_request_referer(client: RegisteredClient, referer: str) -> Dict[str, Any]:
        """
        Validate request referer for a client.
        
        Args:
            client (RegisteredClient): The client
            referer (str): Referer to validate
            
        Returns:
            Dict with validation results
        """
        validator = DomainValidator(client)
        return validator.validate_referer(referer)
    
    @staticmethod
    def validate_request_headers(client: RegisteredClient, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Validate multiple request headers for domain compliance.
        
        Args:
            client (RegisteredClient): The client
            headers (dict): Request headers
            
        Returns:
            Dict with comprehensive validation results
        """
        validator = DomainValidator(client)
        
        origin = headers.get('origin') or headers.get('Origin')
        referer = headers.get('referer') or headers.get('Referer')
        
        results = {
            'client_id': str(client.client_id),
            'overall_valid': True,
            'validations': {}
        }
        
        # Validate origin if present
        if origin:
            origin_result = validator.validate_origin(origin)
            results['validations']['origin'] = origin_result
            if not origin_result['valid']:
                results['overall_valid'] = False
        
        # Validate referer if present
        if referer:
            referer_result = validator.validate_referer(referer)
            results['validations']['referer'] = referer_result
            if not referer_result['valid']:
                results['overall_valid'] = False
        
        # If no origin or referer, check if domain validation is required
        if not origin and not referer and client.allowed_domains:
            results['overall_valid'] = False
            results['validations']['missing_headers'] = {
                'valid': False,
                'reason': 'No origin or referer header provided, but domain validation is required'
            }
        
        return results
    
    @staticmethod
    def add_domain_to_client(client: RegisteredClient, domain: str) -> Dict[str, Any]:
        """
        Add a domain to a client's allowed domains list.
        
        Args:
            client (RegisteredClient): The client
            domain (str): Domain to add
            
        Returns:
            Dict with operation results
        """
        domain = domain.lower().strip()
        
        # Validate domain format
        if not DomainValidationManager._is_valid_domain_format(domain):
            return {
                'success': False,
                'reason': 'Invalid domain format',
                'domain': domain
            }
        
        # Check if domain already exists
        if domain in [d.lower() for d in client.allowed_domains]:
            return {
                'success': False,
                'reason': 'Domain already exists in allowed list',
                'domain': domain
            }
        
        # Add domain
        client.allowed_domains.append(domain)
        client.save()
        
        logger.info(f"Added domain {domain} to client {client.client_name}")
        
        return {
            'success': True,
            'domain': domain,
            'client_id': str(client.client_id),
            'total_domains': len(client.allowed_domains)
        }
    
    @staticmethod
    def remove_domain_from_client(client: RegisteredClient, domain: str) -> Dict[str, Any]:
        """
        Remove a domain from a client's allowed domains list.
        
        Args:
            client (RegisteredClient): The client
            domain (str): Domain to remove
            
        Returns:
            Dict with operation results
        """
        domain = domain.lower().strip()
        
        # Find and remove domain (case-insensitive)
        original_count = len(client.allowed_domains)
        client.allowed_domains = [d for d in client.allowed_domains if d.lower() != domain]
        
        if len(client.allowed_domains) == original_count:
            return {
                'success': False,
                'reason': 'Domain not found in allowed list',
                'domain': domain
            }
        
        client.save()
        
        logger.info(f"Removed domain {domain} from client {client.client_name}")
        
        return {
            'success': True,
            'domain': domain,
            'client_id': str(client.client_id),
            'total_domains': len(client.allowed_domains)
        }
    
    @staticmethod
    def _is_valid_domain_format(domain: str) -> bool:
        """
        Validate domain format.
        
        Args:
            domain (str): Domain to validate
            
        Returns:
            bool: True if format is valid
        """
        # Basic domain format validation
        domain_pattern = r'^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        # Allow port numbers
        if ':' in domain:
            domain_part, port_part = domain.rsplit(':', 1)
            try:
                port = int(port_part)
                if not (1 <= port <= 65535):
                    return False
                domain = domain_part
            except ValueError:
                return False
        
        return bool(re.match(domain_pattern, domain))
    
    @staticmethod
    def get_client_domain_summary(client: RegisteredClient) -> Dict[str, Any]:
        """
        Get domain validation summary for a client.
        
        Args:
            client (RegisteredClient): The client
            
        Returns:
            Dict with domain summary
        """
        validator = DomainValidator(client)
        return validator.get_validation_summary()
