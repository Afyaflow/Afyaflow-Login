"""
GraphQL security middleware for AfyaFlow Auth Service.
Provides query depth limiting, complexity analysis, and security validations.
"""

import logging
from typing import Any, Dict, List
from graphql import GraphQLError, validate, ValidationRule
from graphql.validation import NoSchemaIntrospectionCustomRule
from graphql.language import ast
from django.conf import settings

logger = logging.getLogger(__name__)


class QueryDepthLimitationRule(ValidationRule):
    """Validation rule to limit GraphQL query depth."""
    
    def __init__(self, max_depth: int = 10):
        self.max_depth = max_depth
        super().__init__()
    
    def enter_field(self, node: ast.FieldNode, *_):
        """Check field depth during AST traversal."""
        depth = self._get_depth(node)
        if depth > self.max_depth:
            self.report_error(
                GraphQLError(
                    f"Query depth {depth} exceeds maximum allowed depth of {self.max_depth}",
                    nodes=[node]
                )
            )
    
    def _get_depth(self, node: ast.FieldNode, depth: int = 1) -> int:
        """Calculate the depth of a field node."""
        if not node.selection_set:
            return depth
        
        max_child_depth = depth
        for selection in node.selection_set.selections:
            if isinstance(selection, ast.FieldNode):
                child_depth = self._get_depth(selection, depth + 1)
                max_child_depth = max(max_child_depth, child_depth)
        
        return max_child_depth


class QueryComplexityRule(ValidationRule):
    """Validation rule to limit GraphQL query complexity."""
    
    def __init__(self, max_complexity: int = 1000):
        self.max_complexity = max_complexity
        self.complexity = 0
        super().__init__()
    
    def enter_field(self, node: ast.FieldNode, *_):
        """Calculate complexity during AST traversal."""
        # Simple complexity calculation: each field adds 1, nested fields multiply
        field_complexity = 1
        if node.selection_set:
            field_complexity *= len(node.selection_set.selections)
        
        self.complexity += field_complexity
        
        if self.complexity > self.max_complexity:
            self.report_error(
                GraphQLError(
                    f"Query complexity {self.complexity} exceeds maximum allowed complexity of {self.max_complexity}",
                    nodes=[node]
                )
            )


class SecurityMiddleware:
    """GraphQL middleware for security enhancements."""
    
    def __init__(self):
        self.max_query_depth = getattr(settings, 'GRAPHQL_MAX_QUERY_DEPTH', 10)
        self.max_query_complexity = getattr(settings, 'GRAPHQL_MAX_QUERY_COMPLEXITY', 1000)
        self.enable_introspection = getattr(settings, 'DEBUG', False)
    
    def resolve(self, next, root, info, **args):
        """Apply security checks before resolving."""
        
        # Log GraphQL operations for security monitoring
        operation_name = getattr(info.operation, 'name', None)
        operation_type = info.operation.operation.value if info.operation else 'unknown'
        
        logger.info(
            f"GraphQL {operation_type} operation: {operation_name or 'anonymous'} "
            f"from {self._get_client_ip(info.context)}"
        )
        
        # Apply validation rules
        validation_rules = [
            QueryDepthLimitationRule(self.max_query_depth),
            QueryComplexityRule(self.max_query_complexity),
        ]
        
        # Disable introspection in production
        if not self.enable_introspection:
            validation_rules.append(NoSchemaIntrospectionCustomRule)
        
        # Validate the query
        errors = validate(info.schema, info.context.body, validation_rules)
        if errors:
            logger.warning(f"GraphQL validation errors: {[str(e) for e in errors]}")
            raise errors[0]  # Raise the first validation error
        
        return next(root, info, **args)
    
    def _get_client_ip(self, request) -> str:
        """Get the real client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
        return ip


class AuthenticationLoggingMiddleware:
    """Middleware to log authentication-related GraphQL operations."""
    
    def resolve(self, next, root, info, **args):
        """Log authentication operations."""
        
        # Check if this is an authentication-related mutation
        auth_mutations = [
            'login', 'register', 'loginWithGoogle', 'loginWithMicrosoft', 
            'loginWithLinkedin', 'verifyMfa', 'refreshToken', 'logout',
            'changePassword', 'initiatePasswordReset', 'resetPasswordWithOtp'
        ]
        
        field_name = info.field_name.lower()
        if any(auth_mut in field_name for auth_mut in auth_mutations):
            client_ip = self._get_client_ip(info.context)
            user_agent = info.context.META.get('HTTP_USER_AGENT', 'Unknown')
            
            logger.info(
                f"Authentication operation '{info.field_name}' attempted "
                f"from IP {client_ip} with User-Agent: {user_agent[:100]}"
            )
        
        return next(root, info, **args)
    
    def _get_client_ip(self, request) -> str:
        """Get the real client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
        return ip


# Combine all middleware
class CombinedSecurityMiddleware:
    """Combined security middleware for GraphQL."""
    
    def __init__(self):
        self.security_middleware = SecurityMiddleware()
        self.auth_logging_middleware = AuthenticationLoggingMiddleware()
    
    def resolve(self, next, root, info, **args):
        """Apply all security middleware in sequence."""
        # Apply security checks first
        def security_next(root, info, **args):
            return self.auth_logging_middleware.resolve(next, root, info, **args)
        
        return self.security_middleware.resolve(security_next, root, info, **args)
