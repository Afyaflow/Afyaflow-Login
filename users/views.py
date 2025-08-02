"""
REST API views for the AfyaFlow Auth Service.
Provides token introspection and other service-to-service endpoints.
"""

import json
import logging
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from .service_auth import is_service_request, get_service_context
from .authentication import JWTAuthentication

logger = logging.getLogger(__name__)


@csrf_exempt
@require_http_methods(["POST"])
def token_introspect(request):
    """
    Token introspection endpoint for service-to-service authentication.

    This endpoint allows other services to validate user tokens by sending them
    to the auth service. The auth service validates the token using the appropriate
    user-type-specific secret and returns comprehensive user context.

    Authentication: Requires X-Service-Auth-ID header with valid service account

    Request Body:
    {
        "token": "jwt-token-to-validate"
    }

    Response (Success):
    {
        "active": true,
        "user_id": "uuid",
        "user_email": "user@example.com",
        "user_type": "provider|patient|operations",
        "user_full_name": "John Doe",
        "first_name": "John",
        "last_name": "Doe",
        "current_context": "patient|provider",
        "organization_id": "uuid",
        "permissions": ["read", "write"],
        "user_roles": ["DOCTOR", "ADMIN"],
        "expires_at": 1234567890,
        "token_type": "access|refresh|mfa",
        "is_active": true,
        "is_suspended": false
    }

    Response (Invalid Token):
    {
        "active": false,
        "error": "Token validation failed: Invalid signature"
    }
    """
    # Check service authentication
    if not is_service_request(request):
        logger.warning(f"Token introspection attempted without service auth from {request.META.get('REMOTE_ADDR')}")
        return JsonResponse({
            "error": "Service authentication required",
            "message": "X-Service-Auth-ID header required for this endpoint"
        }, status=401)

    service_account = get_service_context(request)
    if not service_account:
        logger.warning("Service authentication failed - no service account context")
        return JsonResponse({
            "error": "Invalid service account",
            "message": "Service account not found or invalid"
        }, status=401)

    # Check service permissions
    if 'introspect:tokens' not in service_account.permissions:
        logger.warning(f"Service {service_account.service_id} lacks introspection permission")
        return JsonResponse({
            "error": "Insufficient permissions",
            "required_permission": "introspect:tokens",
            "service_permissions": service_account.permissions
        }, status=403)

    try:
        # Parse request body
        data = json.loads(request.body)
        token = data.get('token')

        if not token:
            return JsonResponse({
                "error": "Missing token",
                "message": "Token required in request body"
            }, status=400)

        # Validate token using JWT authentication
        authenticator = JWTAuthentication()

        try:
            # Use the authenticate_token method which handles user-type-specific secrets
            user, payload = authenticator.authenticate_token(token)

            if not user:
                logger.info("Token introspection: Invalid token provided")
                return JsonResponse({
                    "active": False,
                    "error": "Invalid token"
                })

            # Log successful introspection
            logger.info(f"Token introspection successful for user {user.email} by service {service_account.service_id}")

            # Return comprehensive user context
            response_data = {
                "active": True,
                "user_id": str(user.id),
                "user_email": user.email,
                "user_type": payload.get('user_type'),
                "user_full_name": f"{user.first_name} {user.last_name}".strip(),
                "first_name": user.first_name,
                "last_name": user.last_name,
                "current_context": payload.get('current_context'),
                "organization_id": payload.get('org_id'),
                "permissions": payload.get('permissions', []),
                "user_roles": payload.get('roles', []),
                "expires_at": payload.get('exp'),
                "token_type": payload.get('type', 'access'),
                "is_active": user.is_active,
                "is_suspended": getattr(user, 'is_suspended', False)
            }

            return JsonResponse(response_data)

        except Exception as e:
            logger.warning(f"Token validation failed during introspection: {str(e)}")
            return JsonResponse({
                "active": False,
                "error": f"Token validation failed: {str(e)}"
            })

    except json.JSONDecodeError:
        return JsonResponse({
            "error": "Invalid JSON",
            "message": "Request body must be valid JSON"
        }, status=400)
    except Exception as e:
        logger.error(f"Introspection endpoint error: {str(e)}")
        return JsonResponse({
            "error": "Internal server error",
            "message": "An unexpected error occurred"
        }, status=500)


@csrf_exempt
@require_http_methods(["GET"])
def introspection_health(request):
    """
    Health check endpoint for the introspection service.
    Can be called by services to verify auth service connectivity.
    """
    if not is_service_request(request):
        return JsonResponse({
            "error": "Service authentication required"
        }, status=401)

    service_account = get_service_context(request)

    return JsonResponse({
        "status": "healthy",
        "service": "auth-service-introspection",
        "requesting_service": service_account.service_id if service_account else "unknown",
        "timestamp": "2024-01-01T00:00:00Z"  # You might want to use actual timestamp
    })