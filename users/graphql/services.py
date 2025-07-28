import logging
import requests
from django.conf import settings
from django.utils import timezone
from ..models import User, RefreshToken
from ..authentication import create_token, create_oct_token
from datetime import timedelta

# Initialize logger
logger = logging.getLogger(__name__)

def _execute_org_service_query(query: str, variables: dict) -> dict:
    """Helper function to execute a GraphQL query against the Organization Service."""
    org_service_url = getattr(settings, 'ORGANIZATION_SERVICE_URL', None)
    token = getattr(settings, 'INTERNAL_SERVICE_TOKEN', None)

    if not org_service_url or not token:
        logger.error("ORGANIZATION_SERVICE_URL or INTERNAL_SERVICE_TOKEN is not configured.")
        return {}

    try:
        # The URL for a GraphQL service is typically the main endpoint
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }
        payload = {'query': query, 'variables': variables}
        response = requests.post(org_service_url, headers=headers, json=payload, timeout=5)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to execute query on Organization Service: {e}")
        return {}


def get_organization_permissions(user_id: str, organization_id: str) -> list:
    """
    Fetches user's permissions for a given organization from the Organization Service.
    """
    query = """
        query GetUserPermissions($userId: String!, $organizationId: String!) {
            userProfessionalRoles(where: {
                userId: { equals: $userId },
                organizationId: { equals: $organizationId }
            }) {
                role {
                    permissions
                }
            }
        }
    """
    variables = {"userId": str(user_id), "organizationId": str(organization_id)}

    response_data = _execute_org_service_query(query, variables)

    if not response_data or 'errors' in response_data:
        logger.error(f"Error fetching permissions from Org Service: {response_data.get('errors')}")
        return []

    roles = response_data.get('data', {}).get('userProfessionalRoles', [])

    # Flatten the list of permissions from all roles and remove duplicates
    permissions = list(set(p for role_item in roles for p in role_item.get('role', {}).get('permissions', [])))

    logger.info(f"Fetched permissions for user {user_id} in org {organization_id}: {permissions}")
    return permissions


def get_user_organization_roles(user_id: str, organization_id: str) -> list:
    """
    Fetches user's professional roles for a given organization from the Organization Service.
    Returns a list of role names (e.g., ['doctor', 'member']).
    """
    query = """
        query GetUserOrganizationRoles($userId: String!, $organizationId: String!) {
            organizationMemberships(where: {
                userId: { equals: $userId },
                organizationId: { equals: $organizationId }
            }) {
                role
                professionalRoles {
                    role {
                        name
                        category
                    }
                }
            }
        }
    """
    variables = {"userId": str(user_id), "organizationId": str(organization_id)}

    response_data = _execute_org_service_query(query, variables)

    if not response_data or 'errors' in response_data:
        logger.error(f"Error fetching user roles from Org Service: {response_data.get('errors')}")
        return ["member"]  # Default fallback role

    memberships = response_data.get('data', {}).get('organizationMemberships', [])

    if not memberships:
        logger.warning(f"No organization membership found for user {user_id} in org {organization_id}")
        return ["member"]  # Default fallback role

    roles = []

    # Get the first membership (should only be one per user per org)
    membership = memberships[0]

    # Add organization role (e.g., 'ADMIN', 'MEMBER')
    org_role = membership.get('role', '').lower()
    if org_role:
        roles.append(org_role)

    # Add professional roles (e.g., 'doctor', 'nurse')
    professional_roles = membership.get('professionalRoles', [])
    for prof_role in professional_roles:
        role_name = prof_role.get('role', {}).get('name', '').lower()
        if role_name:
            roles.append(role_name)

    # Remove duplicates and ensure we have at least 'member'
    roles = list(set(roles)) if roles else ["member"]

    logger.info(f"Fetched roles for user {user_id} in org {organization_id}: {roles}")
    return roles


def get_user_organization_memberships(user_id: str) -> list:
    """
    Fetches the list of organizations a user is a member of from the Org Service.
    """
    query = """
        query GetUserOrganizationMemberships($userId: String!) {
            organizationMemberships(where: { userId: { equals: $userId } }) {
                organization {
                    id
                    name
                }
            }
        }
    """
    variables = {"userId": str(user_id)}

    response_data = _execute_org_service_query(query, variables)

    if not response_data or 'errors' in response_data:
        logger.error(f"Error fetching organization memberships from Org Service: {response_data.get('errors')}")
        return []

    memberships = response_data.get('data', {}).get('organizationMemberships', [])
    
    logger.info(f"Fetched {len(memberships)} organization memberships for user {user_id}")
    return memberships


def _claim_pending_invitations(user: User):
    """
    Finds pending organization memberships for the user's email and updates them with their user ID.
    This effectively "claims" the invitation upon login.
    """
    mutation = """
        mutation ClaimInvitations($email: String!, $userId: String!) {
            updateManyOrganizationMembership(
                where: {
                    email: { equals: $email },
                    userId: { equals: null },
                    inviteStatus: { equals: PENDING }
                },
                data: {
                    userId: { set: $userId },
                    inviteStatus: { set: ACCEPTED }
                }
            ) {
                count
            }
        }
    """
    variables = {"email": user.email, "userId": str(user.id)}

    response_data = _execute_org_service_query(mutation, variables)
    
    if response_data and not response_data.get('errors'):
        count = response_data.get('data', {}).get('updateManyOrganizationMembership', {}).get('count', 0)
        if count > 0:
            logger.info(f"Successfully claimed {count} pending organization invitations for user {user.email}.")
    else:
        logger.error(f"Failed to claim pending invitations for user {user.email}. Error: {response_data.get('errors')}")


def create_auth_payload(user, mfa_required=False, mfa_token=None, enabled_mfa_methods=None):
    """
    Generates the authentication payload for a user.
    Includes access and refresh tokens unless an MFA step is explicitly required.
    """
    from ..graphql.types import OrganizationMembershipType # Lazy import to avoid circular dependency
    
    # 1. Get organization memberships
    organization_memberships_data = get_user_organization_memberships(user.id)
    
    # 2. Base payload
    payload = {
        "user": user,
        "organization_memberships": [OrganizationMembershipType(**mem) for mem in organization_memberships_data],
        "mfa_required": mfa_required,
        "mfa_token": mfa_token,
        "enabled_mfa_methods": enabled_mfa_methods,
        "access_token": None,
        "refresh_token": None,
    }

    # 3. If MFA is not required, generate and add tokens
    if not mfa_required:
        # Create access token with user type for gateway compliance
        access_token_str, _ = create_token(user.id, token_type='access', user_type=user.user_type)

        # Create and store refresh token with user type for gateway compliance
        refresh_token_str, refresh_expires_at = create_token(user.id, token_type='refresh', user_type=user.user_type)
        
        # Store the refresh token in the database
        RefreshToken.objects.create(
            user=user,
            token=refresh_token_str,
            expires_at=refresh_expires_at
        )

        payload["access_token"] = access_token_str
        payload["refresh_token"] = refresh_token_str

    return payload
