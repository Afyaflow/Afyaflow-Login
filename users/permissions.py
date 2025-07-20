import logging
from typing import List, Dict, Any, Optional, Union
from functools import wraps
from django.core.exceptions import PermissionDenied
from django.core.cache import cache
from graphql import GraphQLError

from .models import User, UserRole, ServiceAccount

logger = logging.getLogger(__name__)


class PermissionError(Exception):
    """Custom exception for permission-related errors."""
    pass


class PermissionChecker:
    """
    Utility class for checking user permissions based on roles.
    """
    
    def __init__(self, user: User):
        self.user = user
        self._cached_permissions = None
    
    def has_permission(self, permission: str) -> bool:
        """
        Check if user has a specific permission.
        
        Args:
            permission (str): Permission to check
            
        Returns:
            bool: True if user has permission
        """
        user_permissions = self.get_all_permissions()
        return permission in user_permissions
    
    def has_any_permission(self, permissions: List[str]) -> bool:
        """
        Check if user has any of the specified permissions.
        
        Args:
            permissions (List[str]): List of permissions to check
            
        Returns:
            bool: True if user has at least one permission
        """
        user_permissions = self.get_all_permissions()
        return any(perm in user_permissions for perm in permissions)
    
    def has_all_permissions(self, permissions: List[str]) -> bool:
        """
        Check if user has all of the specified permissions.
        
        Args:
            permissions (List[str]): List of permissions to check
            
        Returns:
            bool: True if user has all permissions
        """
        user_permissions = self.get_all_permissions()
        return all(perm in user_permissions for perm in permissions)
    
    def get_all_permissions(self) -> List[str]:
        """
        Get all permissions for the user based on their active roles.
        
        Returns:
            List[str]: List of all permissions
        """
        if self._cached_permissions is not None:
            return self._cached_permissions
        
        permissions = set()
        
        # Get permissions from all active roles
        for role in self.user.get_active_roles():
            permissions.update(role.permissions)
        
        # Add superuser permissions
        if self.user.is_superuser:
            permissions.update(self._get_superuser_permissions())
        
        self._cached_permissions = list(permissions)
        return self._cached_permissions
    
    def get_role_permissions(self, role_name: str) -> List[str]:
        """
        Get permissions for a specific role.
        
        Args:
            role_name (str): Name of the role
            
        Returns:
            List[str]: List of permissions for the role
        """
        try:
            role = UserRole.objects.get(name=role_name, is_active=True)
            return role.permissions
        except UserRole.DoesNotExist:
            return []
    
    def check_resource_access(self, resource_type: str, resource_id: str = None, 
                            action: str = 'view') -> bool:
        """
        Check if user can access a specific resource.
        
        Args:
            resource_type (str): Type of resource (e.g., 'patient', 'medical_record')
            resource_id (str, optional): Specific resource ID
            action (str): Action to perform ('view', 'create', 'update', 'delete')
            
        Returns:
            bool: True if access is allowed
        """
        # Build permission string
        permission = f"{action}_{resource_type}"
        
        # Check basic permission
        if not self.has_permission(permission):
            return False
        
        # Additional checks for specific resources
        if resource_id:
            return self._check_resource_ownership(resource_type, resource_id)
        
        return True
    
    def get_accessible_resources(self, resource_type: str) -> Dict[str, List[str]]:
        """
        Get list of resources the user can access and what actions they can perform.
        
        Args:
            resource_type (str): Type of resource
            
        Returns:
            Dict with accessible resources and allowed actions
        """
        actions = ['view', 'create', 'update', 'delete']
        accessible = {
            'allowed_actions': [],
            'restrictions': []
        }
        
        for action in actions:
            permission = f"{action}_{resource_type}"
            if self.has_permission(permission):
                accessible['allowed_actions'].append(action)
        
        # Add role-specific restrictions
        if self.user.is_patient():
            accessible['restrictions'].append('own_records_only')
        elif self.user.is_provider():
            accessible['restrictions'].append('organization_patients_only')
        
        return accessible
    
    def _check_resource_ownership(self, resource_type: str, resource_id: str) -> bool:
        """
        Check if user owns or has access to a specific resource.
        
        Args:
            resource_type (str): Type of resource
            resource_id (str): Resource ID
            
        Returns:
            bool: True if user has access
        """
        # This would typically query the database to check ownership
        # For now, implement basic logic
        
        if self.user.is_admin_user():
            return True  # Admins can access everything
        
        if resource_type == 'patient' and self.user.is_patient():
            # Patients can only access their own records
            return str(self.user.id) == resource_id
        
        if resource_type == 'medical_record' and self.user.is_provider():
            # Providers can access records of their patients
            # This would need to check the actual relationship
            return True  # Simplified for now
        
        return False
    
    def _get_superuser_permissions(self) -> List[str]:
        """
        Get all permissions for superusers.
        
        Returns:
            List[str]: All available permissions
        """
        return [
            'view_all_users',
            'manage_users',
            'manage_organizations',
            'view_system_logs',
            'manage_system_settings',
            'access_admin_interface',
            'view_patient_records',
            'create_medical_records',
            'update_medical_records',
            'delete_medical_records',
            'manage_user_roles',
            'view_audit_logs'
        ]
    
    def clear_cache(self):
        """Clear cached permissions."""
        self._cached_permissions = None


class RoleBasedPermissionManager:
    """
    Manager class for role-based permission operations.
    """
    
    @staticmethod
    def check_user_permission(user: User, permission: str) -> bool:
        """
        Check if a user has a specific permission.
        
        Args:
            user (User): User to check
            permission (str): Permission to check
            
        Returns:
            bool: True if user has permission
        """
        checker = PermissionChecker(user)
        return checker.has_permission(permission)
    
    @staticmethod
    def get_user_permissions(user: User) -> List[str]:
        """
        Get all permissions for a user.
        
        Args:
            user (User): User to get permissions for
            
        Returns:
            List[str]: List of permissions
        """
        checker = PermissionChecker(user)
        return checker.get_all_permissions()
    
    @staticmethod
    def check_resource_access(user: User, resource_type: str, resource_id: str = None, 
                            action: str = 'view') -> bool:
        """
        Check if user can access a resource.
        
        Args:
            user (User): User to check
            resource_type (str): Type of resource
            resource_id (str, optional): Specific resource ID
            action (str): Action to perform
            
        Returns:
            bool: True if access is allowed
        """
        checker = PermissionChecker(user)
        return checker.check_resource_access(resource_type, resource_id, action)
    
    @staticmethod
    def get_permission_summary(user: User) -> Dict[str, Any]:
        """
        Get comprehensive permission summary for a user.
        
        Args:
            user (User): User to get summary for
            
        Returns:
            Dict with permission summary
        """
        checker = PermissionChecker(user)
        
        return {
            'user_id': str(user.id),
            'user_email': user.email,
            'primary_role': user.get_primary_role_name(),
            'active_roles': [role.name for role in user.get_active_roles()],
            'all_permissions': checker.get_all_permissions(),
            'is_superuser': user.is_superuser,
            'resource_access': {
                'patients': checker.get_accessible_resources('patient'),
                'medical_records': checker.get_accessible_resources('medical_record'),
                'organizations': checker.get_accessible_resources('organization')
            }
        }


def require_permission(permission: str):
    """
    Decorator to require a specific permission for a function.
    
    Args:
        permission (str): Required permission
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Try to get user from different argument positions
            user = None
            
            # Check if it's a method with self/cls and info
            if len(args) >= 3 and hasattr(args[2], 'context'):
                user = getattr(args[2].context, 'user', None)
            # Check if user is passed directly
            elif len(args) >= 1 and isinstance(args[0], User):
                user = args[0]
            # Check in kwargs
            elif 'user' in kwargs:
                user = kwargs['user']
            
            if not user or not user.is_authenticated:
                raise PermissionDenied("Authentication required")
            
            checker = PermissionChecker(user)
            if not checker.has_permission(permission):
                raise PermissionDenied(f"Permission '{permission}' required")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_any_permission(permissions: List[str]):
    """
    Decorator to require any of the specified permissions.
    
    Args:
        permissions (List[str]): List of permissions (user needs at least one)
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = None
            
            if len(args) >= 3 and hasattr(args[2], 'context'):
                user = getattr(args[2].context, 'user', None)
            elif len(args) >= 1 and isinstance(args[0], User):
                user = args[0]
            elif 'user' in kwargs:
                user = kwargs['user']
            
            if not user or not user.is_authenticated:
                raise PermissionDenied("Authentication required")
            
            checker = PermissionChecker(user)
            if not checker.has_any_permission(permissions):
                raise PermissionDenied(f"One of these permissions required: {', '.join(permissions)}")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_role(role_name: str):
    """
    Decorator to require a specific role.
    
    Args:
        role_name (str): Required role name
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = None
            
            if len(args) >= 3 and hasattr(args[2], 'context'):
                user = getattr(args[2].context, 'user', None)
            elif len(args) >= 1 and isinstance(args[0], User):
                user = args[0]
            elif 'user' in kwargs:
                user = kwargs['user']
            
            if not user or not user.is_authenticated:
                raise PermissionDenied("Authentication required")
            
            if not user.has_role(role_name):
                raise PermissionDenied(f"Role '{role_name}' required")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def require_any_role(roles: List[str]):
    """
    Decorator to require any of the specified roles.
    
    Args:
        roles (List[str]): List of role names (user needs at least one)
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = None
            
            if len(args) >= 3 and hasattr(args[2], 'context'):
                user = getattr(args[2].context, 'user', None)
            elif len(args) >= 1 and isinstance(args[0], User):
                user = args[0]
            elif 'user' in kwargs:
                user = kwargs['user']
            
            if not user or not user.is_authenticated:
                raise PermissionDenied("Authentication required")
            
            user_roles = [role.name for role in user.get_active_roles()]
            if not any(role in user_roles for role in roles):
                raise PermissionDenied(f"One of these roles required: {', '.join(roles)}")
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


# GraphQL-specific permission decorators
def graphql_require_permission(permission: str):
    """
    GraphQL-specific decorator to require a permission.
    
    Args:
        permission (str): Required permission
    """
    def decorator(func):
        @wraps(func)
        def wrapper(cls, root, info, *args, **kwargs):
            user = getattr(info.context, 'user', None)
            
            if not user or not user.is_authenticated:
                raise GraphQLError(
                    "Authentication required",
                    extensions={"code": "AUTHENTICATION_REQUIRED"}
                )
            
            checker = PermissionChecker(user)
            if not checker.has_permission(permission):
                raise GraphQLError(
                    f"Permission '{permission}' required",
                    extensions={"code": "PERMISSION_DENIED", "required_permission": permission}
                )
            
            return func(cls, root, info, *args, **kwargs)
        return wrapper
    return decorator


def graphql_require_role(role_name: str):
    """
    GraphQL-specific decorator to require a role.
    
    Args:
        role_name (str): Required role name
    """
    def decorator(func):
        @wraps(func)
        def wrapper(cls, root, info, *args, **kwargs):
            user = getattr(info.context, 'user', None)
            
            if not user or not user.is_authenticated:
                raise GraphQLError(
                    "Authentication required",
                    extensions={"code": "AUTHENTICATION_REQUIRED"}
                )
            
            if not user.has_role(role_name):
                raise GraphQLError(
                    f"Role '{role_name}' required",
                    extensions={"code": "ROLE_REQUIRED", "required_role": role_name}
                )
            
            return func(cls, root, info, *args, **kwargs)
        return wrapper
    return decorator


class ServicePermissionChecker:
    """
    Permission checker for service accounts with enhanced capabilities.
    """

    # Cache timeout for permission checks (5 minutes)
    CACHE_TIMEOUT = 300

    # Permission separators and wildcards
    RESOURCE_SEPARATOR = ':'
    WILDCARD = '*'

    def __init__(self, service_account: ServiceAccount):
        self.service_account = service_account

    def has_permission(self, permission: str, resource_id: str = None) -> bool:
        """
        Check if service account has a specific permission.

        Args:
            permission (str): Permission to check (e.g., 'read:patients')
            resource_id (str, optional): Specific resource ID for fine-grained control

        Returns:
            bool: True if service account has permission
        """
        if not self.service_account or not self.service_account.is_active:
            return False

        return self._has_permission(self.service_account.permissions, permission, resource_id)

    def _has_permission(self, available_permissions: List[str], required_permission: str,
                       resource_id: str = None) -> bool:
        """
        Check if a required permission is available in the list.
        Supports wildcards and resource-specific permissions.
        """
        if not available_permissions:
            return False

        # Direct match
        if required_permission in available_permissions:
            return True

        # Check for wildcard permissions
        for available_perm in available_permissions:
            if self._permission_matches(available_perm, required_permission, resource_id):
                return True

        return False

    def _permission_matches(self, available_perm: str, required_perm: str, resource_id: str = None) -> bool:
        """
        Check if an available permission matches a required permission.
        Supports various wildcard patterns and resource-specific matching.
        """
        # Exact match
        if available_perm == required_perm:
            return True

        # Global wildcard
        if available_perm == self.WILDCARD:
            return True

        # Parse permissions
        available_parts = available_perm.split(self.RESOURCE_SEPARATOR)
        required_parts = required_perm.split(self.RESOURCE_SEPARATOR)

        if len(available_parts) == 2 and len(required_parts) == 2:
            # Standard resource:action format
            return self._match_resource_action(available_parts, required_parts)

        return False

    def _match_resource_action(self, available_parts: List[str], required_parts: List[str]) -> bool:
        """Match resource:action permission format."""
        available_resource, available_action = available_parts
        required_resource, required_action = required_parts

        # Check resource match
        resource_match = (
            available_resource == self.WILDCARD or
            available_resource == required_resource or
            self._match_permission_part(available_resource, required_resource)
        )

        # Check action match
        action_match = (
            available_action == self.WILDCARD or
            available_action == required_action or
            self._match_permission_part(available_action, required_action)
        )

        return resource_match and action_match

    def _match_permission_part(self, available_part: str, required_part: str) -> bool:
        """Match individual permission parts with wildcard support."""
        if available_part == self.WILDCARD:
            return True

        if available_part == required_part:
            return True

        # Pattern matching (e.g., 'patient_*' matches 'patient_123')
        if self.WILDCARD in available_part:
            pattern = available_part.replace(self.WILDCARD, '.*')
            import re
            return bool(re.match(f'^{pattern}$', required_part))

        return False

    def get_all_permissions(self) -> List[str]:
        """Get all permissions for this service account."""
        if self.service_account and self.service_account.is_active:
            return self.service_account.permissions
        return []

    def has_any_permission(self, permissions: List[str]) -> bool:
        """Check if service account has any of the specified permissions."""
        return any(self.has_permission(perm) for perm in permissions)

    def require_permission(self, permission: str, resource_id: str = None):
        """Require a specific permission, raise error if not available."""
        if not self.has_permission(permission, resource_id):
            raise PermissionError(f"Service permission required: {permission}")


def require_service_permission(permission: str, resource_id: str = None):
    """
    Decorator to require a specific service permission for GraphQL resolvers.

    Args:
        permission (str): Required permission
        resource_id (str, optional): Specific resource ID
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract info from args (GraphQL resolver pattern)
            info = None
            for arg in args:
                if hasattr(arg, 'context'):
                    info = arg
                    break

            if not info:
                raise GraphQLError("Unable to determine request context")

            request = info.context

            # Check for service authentication
            if hasattr(request, 'service_account'):
                service_checker = ServicePermissionChecker(request.service_account)
                if not service_checker.has_permission(permission, resource_id):
                    raise GraphQLError(f"Service permission required: {permission}")
            else:
                raise GraphQLError("Service authentication required")

            return func(*args, **kwargs)

        return wrapper
    return decorator


def check_service_or_user_permission(permission: str, resource_id: str = None):
    """
    Decorator that allows either service account or user permission.

    Args:
        permission (str): Required permission
        resource_id (str, optional): Specific resource ID
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract info from args
            info = None
            for arg in args:
                if hasattr(arg, 'context'):
                    info = arg
                    break

            if not info:
                raise GraphQLError("Unable to determine request context")

            request = info.context
            has_permission = False

            # Check service account permission
            if hasattr(request, 'service_account'):
                service_checker = ServicePermissionChecker(request.service_account)
                has_permission = service_checker.has_permission(permission, resource_id)

            # Check user permission if service permission not available
            if not has_permission and hasattr(request, 'user') and request.user.is_authenticated:
                user_checker = PermissionChecker(request.user)
                has_permission = user_checker.has_permission(permission)

            if not has_permission:
                raise GraphQLError(f"Permission required: {permission}")

            return func(*args, **kwargs)

        return wrapper
    return decorator
