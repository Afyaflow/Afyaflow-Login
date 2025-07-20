import logging
from django.db import transaction
from django.utils import timezone
from django.core.exceptions import ValidationError, PermissionDenied
from datetime import timedelta
from typing import List, Dict, Any, Optional

from .models import User, UserRole, UserRoleAssignment

logger = logging.getLogger(__name__)


class RoleAssignmentError(Exception):
    """Custom exception for role assignment errors."""
    pass


class RoleManager:
    """
    Manages role assignments with comprehensive validation and audit trails.
    """
    
    def __init__(self, user: User, assigned_by: User = None):
        self.user = user
        self.assigned_by = assigned_by
    
    @transaction.atomic
    def assign_role(self, role_name: str, expires_at: timezone.datetime = None, 
                   reason: str = None) -> UserRoleAssignment:
        """
        Assign a role to the user with comprehensive validation.
        
        Args:
            role_name (str): Name of the role to assign
            expires_at (datetime, optional): When the role assignment expires
            reason (str, optional): Reason for role assignment
            
        Returns:
            UserRoleAssignment: The created role assignment
            
        Raises:
            RoleAssignmentError: If role assignment fails validation
        """
        # Validate role exists and is active
        try:
            role = UserRole.objects.get(name=role_name, is_active=True)
        except UserRole.DoesNotExist:
            raise RoleAssignmentError(f"Role '{role_name}' does not exist or is not active")
        
        # Check if user already has this role
        existing_assignment = UserRoleAssignment.objects.filter(
            user=self.user,
            role=role,
            is_active=True
        ).first()
        
        if existing_assignment:
            if not existing_assignment.is_expired:
                raise RoleAssignmentError(f"User already has active role '{role_name}'")
            else:
                # Reactivate expired assignment
                existing_assignment.is_active = True
                existing_assignment.expires_at = expires_at
                existing_assignment.assigned_by = self.assigned_by
                existing_assignment.save()
                
                self._log_role_operation('role_reactivated', role, reason)
                return existing_assignment
        
        # Validate role assignment rules
        self._validate_role_assignment(role)
        
        # Create new role assignment
        assignment = UserRoleAssignment.objects.create(
            user=self.user,
            role=role,
            assigned_by=self.assigned_by,
            expires_at=expires_at,
            is_active=True
        )
        
        # Set as primary role if user doesn't have one
        if not self.user.primary_role:
            self.user.primary_role = role
            self.user.save(update_fields=['primary_role'])
        
        self._log_role_operation('role_assigned', role, reason)
        
        logger.info(f"Assigned role '{role_name}' to user {self.user.email}")
        return assignment
    
    @transaction.atomic
    def remove_role(self, role_name: str, reason: str = None) -> bool:
        """
        Remove a role from the user.
        
        Args:
            role_name (str): Name of the role to remove
            reason (str, optional): Reason for role removal
            
        Returns:
            bool: True if role was removed, False if not found
            
        Raises:
            RoleAssignmentError: If role removal fails validation
        """
        try:
            role = UserRole.objects.get(name=role_name)
        except UserRole.DoesNotExist:
            raise RoleAssignmentError(f"Role '{role_name}' does not exist")
        
        # Find active assignment
        assignment = UserRoleAssignment.objects.filter(
            user=self.user,
            role=role,
            is_active=True
        ).first()
        
        if not assignment:
            return False
        
        # Validate role removal
        self._validate_role_removal(role)
        
        # Deactivate assignment
        assignment.is_active = False
        assignment.save()
        
        # Clear primary role if it was removed
        if self.user.primary_role == role:
            # Set to another active role if available
            other_roles = self.user.get_active_roles().exclude(id=role.id)
            self.user.primary_role = other_roles.first()
            self.user.save(update_fields=['primary_role'])
        
        self._log_role_operation('role_removed', role, reason)
        
        logger.info(f"Removed role '{role_name}' from user {self.user.email}")
        return True
    
    @transaction.atomic
    def update_primary_role(self, role_name: str, reason: str = None) -> bool:
        """
        Update the user's primary role.
        
        Args:
            role_name (str): Name of the role to set as primary
            reason (str, optional): Reason for change
            
        Returns:
            bool: True if primary role was updated
            
        Raises:
            RoleAssignmentError: If role is not assigned to user
        """
        try:
            role = UserRole.objects.get(name=role_name, is_active=True)
        except UserRole.DoesNotExist:
            raise RoleAssignmentError(f"Role '{role_name}' does not exist or is not active")
        
        # Check if user has this role
        if not self.user.has_role(role_name):
            raise RoleAssignmentError(f"User does not have role '{role_name}'")
        
        old_primary = self.user.primary_role
        self.user.primary_role = role
        self.user.save(update_fields=['primary_role'])
        
        self._log_role_operation('primary_role_changed', role, reason, {
            'old_primary_role': old_primary.name if old_primary else None,
            'new_primary_role': role.name
        })
        
        logger.info(f"Updated primary role to '{role_name}' for user {self.user.email}")
        return True
    
    def get_role_history(self, role_name: str = None) -> List[UserRoleAssignment]:
        """
        Get role assignment history for the user.
        
        Args:
            role_name (str, optional): Filter by specific role
            
        Returns:
            List of UserRoleAssignment objects
        """
        queryset = UserRoleAssignment.objects.filter(user=self.user)
        
        if role_name:
            queryset = queryset.filter(role__name=role_name)
        
        return list(queryset.select_related('role', 'assigned_by').order_by('-assigned_at'))
    
    def get_role_summary(self) -> Dict[str, Any]:
        """
        Get comprehensive role summary for the user.
        
        Returns:
            Dict with role information
        """
        active_roles = self.user.get_active_roles()
        
        return {
            'user_id': str(self.user.id),
            'user_email': self.user.email,
            'primary_role': self.user.primary_role.name if self.user.primary_role else None,
            'active_roles': [
                {
                    'name': role.name,
                    'description': role.description,
                    'permissions': role.permissions,
                    'assigned_at': self._get_assignment_date(role)
                }
                for role in active_roles
            ],
            'total_active_roles': active_roles.count(),
            'role_history_count': UserRoleAssignment.objects.filter(user=self.user).count()
        }
    
    def _validate_role_assignment(self, role: UserRole):
        """
        Validate role assignment rules.
        
        Args:
            role (UserRole): Role to validate
            
        Raises:
            RoleAssignmentError: If validation fails
        """
        # Check role compatibility
        current_roles = set(self.user.get_active_roles().values_list('name', flat=True))
        
        # Business rules for role compatibility
        incompatible_combinations = {
            'PATIENT': ['PROVIDER', 'ADMIN'],
            'PROVIDER': ['PATIENT'],
            'ADMIN': ['PATIENT']
        }
        
        if role.name in incompatible_combinations:
            for incompatible_role in incompatible_combinations[role.name]:
                if incompatible_role in current_roles:
                    raise RoleAssignmentError(
                        f"Role '{role.name}' is incompatible with existing role '{incompatible_role}'"
                    )
        
        # Check if assigner has permission to assign this role
        if self.assigned_by and not self._can_assign_role(role):
            raise RoleAssignmentError(
                f"User {self.assigned_by.email} does not have permission to assign role '{role.name}'"
            )
    
    def _validate_role_removal(self, role: UserRole):
        """
        Validate role removal rules.
        
        Args:
            role (UserRole): Role to validate removal
            
        Raises:
            RoleAssignmentError: If validation fails
        """
        # Prevent removal of last role
        active_roles = self.user.get_active_roles()
        if active_roles.count() == 1 and role in active_roles:
            raise RoleAssignmentError("Cannot remove the last active role from user")
        
        # Check if remover has permission
        if self.assigned_by and not self._can_remove_role(role):
            raise RoleAssignmentError(
                f"User {self.assigned_by.email} does not have permission to remove role '{role.name}'"
            )
    
    def _can_assign_role(self, role: UserRole) -> bool:
        """
        Check if the assigner can assign the specified role.
        
        Args:
            role (UserRole): Role to check
            
        Returns:
            bool: True if assignment is allowed
        """
        if not self.assigned_by:
            return True  # System assignment
        
        # Admins can assign any role
        if self.assigned_by.is_admin_user():
            return True
        
        # Providers can assign PATIENT roles
        if self.assigned_by.is_provider() and role.name == 'PATIENT':
            return True
        
        return False
    
    def _can_remove_role(self, role: UserRole) -> bool:
        """
        Check if the remover can remove the specified role.
        
        Args:
            role (UserRole): Role to check
            
        Returns:
            bool: True if removal is allowed
        """
        if not self.assigned_by:
            return True  # System removal
        
        # Admins can remove any role
        if self.assigned_by.is_admin_user():
            return True
        
        # Users can remove their own PATIENT role
        if (self.assigned_by == self.user and role.name == 'PATIENT'):
            return True
        
        return False
    
    def _get_assignment_date(self, role: UserRole) -> Optional[str]:
        """
        Get the assignment date for a role.
        
        Args:
            role (UserRole): Role to get assignment date for
            
        Returns:
            str or None: ISO formatted assignment date
        """
        assignment = UserRoleAssignment.objects.filter(
            user=self.user,
            role=role,
            is_active=True
        ).first()
        
        return assignment.assigned_at.isoformat() if assignment else None
    
    def _log_role_operation(self, operation: str, role: UserRole, reason: str = None, 
                          additional_data: Dict[str, Any] = None):
        """
        Log role operation for audit trail.
        
        Args:
            operation (str): Type of operation
            role (UserRole): Role involved
            reason (str, optional): Reason for operation
            additional_data (dict, optional): Additional data to log
        """
        log_data = {
            'operation': operation,
            'user_id': str(self.user.id),
            'user_email': self.user.email,
            'role_name': role.name,
            'assigned_by': self.assigned_by.email if self.assigned_by else 'system',
            'timestamp': timezone.now().isoformat(),
            'reason': reason
        }
        
        if additional_data:
            log_data.update(additional_data)
        
        logger.info(f"Role operation: {operation} - {log_data}")


class RoleValidationService:
    """
    Service for validating role-related operations.
    """
    
    @staticmethod
    def validate_role_transition(user: User, from_role: str, to_role: str) -> Dict[str, Any]:
        """
        Validate a role transition.
        
        Args:
            user (User): User transitioning roles
            from_role (str): Current role
            to_role (str): Target role
            
        Returns:
            Dict with validation results
        """
        # Define allowed transitions
        allowed_transitions = {
            'PATIENT': ['PROVIDER'],  # Patients can become providers
            'PROVIDER': ['ADMIN'],    # Providers can become admins
            'ADMIN': []               # Admins cannot transition (would need to be removed and re-added)
        }
        
        if to_role not in allowed_transitions.get(from_role, []):
            return {
                'valid': False,
                'reason': f"Transition from {from_role} to {to_role} is not allowed",
                'allowed_transitions': allowed_transitions.get(from_role, [])
            }
        
        return {
            'valid': True,
            'reason': f"Transition from {from_role} to {to_role} is allowed"
        }
    
    @staticmethod
    def get_role_requirements(role_name: str) -> Dict[str, Any]:
        """
        Get requirements for a specific role.
        
        Args:
            role_name (str): Name of the role
            
        Returns:
            Dict with role requirements
        """
        requirements = {
            'PATIENT': {
                'email_verified': True,
                'phone_verified': False,
                'mfa_required': False,
                'background_check': False
            },
            'PROVIDER': {
                'email_verified': True,
                'phone_verified': True,
                'mfa_required': True,
                'background_check': True,
                'license_verification': True
            },
            'ADMIN': {
                'email_verified': True,
                'phone_verified': True,
                'mfa_required': True,
                'background_check': True,
                'admin_approval': True
            }
        }
        
        return requirements.get(role_name, {})
    
    @staticmethod
    def check_role_requirements(user: User, role_name: str) -> Dict[str, Any]:
        """
        Check if user meets requirements for a role.
        
        Args:
            user (User): User to check
            role_name (str): Role to check requirements for
            
        Returns:
            Dict with requirement check results
        """
        requirements = RoleValidationService.get_role_requirements(role_name)
        results = {
            'meets_requirements': True,
            'failed_requirements': [],
            'requirements': requirements
        }
        
        # Check email verification
        if requirements.get('email_verified') and not user.email_verified:
            results['meets_requirements'] = False
            results['failed_requirements'].append('email_verified')
        
        # Check phone verification
        if requirements.get('phone_verified') and not user.phone_number_verified:
            results['meets_requirements'] = False
            results['failed_requirements'].append('phone_verified')
        
        # Check MFA setup
        if requirements.get('mfa_required') and not user.mfa_totp_setup_complete:
            results['meets_requirements'] = False
            results['failed_requirements'].append('mfa_required')
        
        return results
