import logging
import requests
from django.conf import settings
from django.utils import timezone
from ..models import User, RefreshToken
from ..authentication import create_token, create_oct_token
from graphql import GraphQLError
import json

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
    
    # Extract just the organization data from the membership object
    organizations = [
        membership['organization'] 
        for membership in memberships 
        if 'organization' in membership
    ]
    
    logger.info(f"Fetched {len(organizations)} organization memberships for user {user_id}")
    return organizations


def create_auth_payload(user, organization_id=None):
    """
    Creates JWTs and saves the refresh token.
    If organization_id is provided, it also creates an Organization Context Token.
    """
    access_token_str, _ = create_token(user.id, token_type='access')
    refresh_token_str, refresh_expires_at = create_token(user.id, token_type='refresh')

    RefreshToken.objects.create(
        user=user,
        token=refresh_token_str,
        expires_at=refresh_expires_at
    )
    
    # Update last_login
    user.last_login = timezone.now()
    user.save(update_fields=['last_login'])

    logger.info(f"Successfully created tokens for user {user.email}")
    
    # Always fetch the user's organization memberships on login
    organization_memberships_data = get_user_organization_memberships(user.id)

    payload = {
        "user": user,
        "access_token": access_token_str,
        "refresh_token": refresh_token_str,
        "organization_memberships": organization_memberships_data,
    }

    if organization_id:
        permissions = get_organization_permissions(user.id, organization_id)
        if permissions:
            oct_token_str, _ = create_oct_token(user.id, organization_id, permissions)
            payload["organization_context_token"] = oct_token_str
            logger.info(f"Successfully created OCT for user {user.email} in organization {organization_id}")
        else:
            logger.warning(f"Could not create OCT for user {user.email}: No permissions found for organization {organization_id}")


    return payload

class GoogleAuthService:
    """
    Service to handle Google OAuth2 authentication.
    """
    TOKEN_INFO_URL = 'https://oauth2.googleapis.com/tokeninfo'

    def __init__(self, id_token):
        self.id_token = id_token
        self.client_id = getattr(settings, 'GOOGLE_CLIENT_ID', None)

    def validate_token(self):
        """
        Validates the Google ID token and returns the token info.
        """
        if not self.client_id:
            logger.error("GoogleAuthService: GOOGLE_CLIENT_ID setting is not configured.")
            raise ValueError("Server configuration error: Google Client ID not set.")

        try:
            response = requests.get(f'{self.TOKEN_INFO_URL}?id_token={self.id_token}')
            response.raise_for_status()  # Raises an HTTPError for bad responses (4xx or 5xx)
            token_info = response.json()
            
            # Verify audience
            if token_info.get('aud') != self.client_id:
                raise ValueError("ID token audience mismatch.")
            
            # Verify issuer
            issuer = token_info.get('iss')
            if issuer not in ['accounts.google.com', 'https://accounts.google.com']:
                raise ValueError("Invalid ID token issuer.")

            if not token_info.get('email_verified', False):
                raise ValueError("Email not verified with Google.")

            return token_info

        except requests.RequestException as e:
            logger.error(f"GoogleAuthService: Error validating Google ID token: {e}")
            raise ValueError("Error validating Google ID token.")
        except Exception as e:
            logger.error(f"GoogleAuthService: Unexpected error during token validation: {e}")
            raise ValueError(f"An unexpected error occurred: {str(e)}")

    @staticmethod
    def get_or_create_user(token_info):
        """
        Gets an existing user or creates a new one based on the token info.
        Links the social account.
        """
        google_user_id = token_info.get('sub')
        email = token_info.get('email')

        if not google_user_id or not email:
            raise ValueError("Required user information (sub, email) not in token.")

        from allauth.socialaccount.models import SocialAccount

        try:
            # Find user by social account
            social_account = SocialAccount.objects.get(provider='google', uid=google_user_id)
            user = social_account.user
            logger.info(f"Found existing social account for user {user.email}")
            social_account.extra_data = token_info
            social_account.save()
            return user
        except SocialAccount.DoesNotExist:
            try:
                # Find user by email and link account
                user = User.objects.get(email=email)
                logger.info(f"Found existing user with email {email}, linking social account.")
            except User.DoesNotExist:
                # Create a new user
                logger.info(f"Creating new user for email {email}")
                given_name = token_info.get('given_name', '')
                family_name = token_info.get('family_name', '')
                if not given_name and not family_name and token_info.get('name'):
                    parts = token_info.get('name').split(' ', 1)
                    given_name = parts[0]
                    family_name = parts[1] if len(parts) > 1 else ''

                user = User(
                    email=email,
                    first_name=given_name,
                    last_name=family_name,
                    is_active=True
                )
                user.set_unusable_password()
                user.save()
            
            # Create the social account link
            SocialAccount.objects.create(
                user=user,
                provider='google',
                uid=google_user_id,
                extra_data=token_info
            )
            return user

def get_organization_context(user, organization_id, internal_service_token):
    # ... existing code ...
    except requests.RequestException as e:
        # The organization service might be down or there's a network issue
        return None, f"Failed to connect to the organization service: {e}"
    except Exception as e:
        # Catch any other unexpected errors
        return None, f"An unexpected error occurred while fetching organization context: {e}"

def send_templated_email(recipient: str, template_id: str, context: dict):
    """
    Calls the communication microservice to send a templated email.
    """
    comm_service_url = getattr(settings, 'COMMUNICATION_SERVICE_URL', None)
    if not comm_service_url:
        logger.warning("COMMUNICATION_SERVICE_URL is not set. Skipping email.")
        return

    mutation = """
    mutation SendTemplatedEmail($recipient: String!, $templateId: String!, $contextJson: String!) {
      sendTemplatedEmail(recipient: $recipient, templateId: $templateId, contextJson: $contextJson) {
        success
        message
      }
    }
    """

    variables = {
        "recipient": recipient,
        "templateId": template_id,
        "contextJson": json.dumps(context)
    }

    try:
        response = requests.post(
            comm_service_url,
            json={'query': mutation, 'variables': variables},
            timeout=5  # 5-second timeout
        )
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        
        response_data = response.json()
        if 'errors' in response_data:
            logger.error(f"Error from communication service: {response_data['errors']}")
        else:
            logger.info(f"Successfully queued email via communication service: {response_data}")

    except requests.RequestException as e:
        # Handle network errors, timeouts, etc.
        logger.error(f"Error sending email request to communication service: {e}")
    except Exception as e:
        # Handle other errors (e.g., JSON decoding)
        logger.error(f"An unexpected error occurred when trying to send an email: {e}")
