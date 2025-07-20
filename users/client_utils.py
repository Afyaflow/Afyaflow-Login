import secrets
import hashlib
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


def generate_api_key(length=32):
    """
    Generate a secure API key for client authentication.
    
    Args:
        length (int): Length of the API key in bytes (default: 32)
        
    Returns:
        str: Base64-encoded API key
    """
    # Generate random bytes
    random_bytes = secrets.token_bytes(length)
    
    # Encode as base64 for easier handling
    api_key = base64.urlsafe_b64encode(random_bytes).decode('utf-8')
    
    # Remove padding for cleaner appearance
    api_key = api_key.rstrip('=')
    
    logger.info(f"Generated API key of length {len(api_key)}")
    return api_key


def hash_api_key(api_key):
    """
    Hash an API key for secure storage.
    
    Args:
        api_key (str): The API key to hash
        
    Returns:
        str: Hashed API key
    """
    # Use SHA-256 with a salt for hashing
    salt = getattr(settings, 'SECRET_KEY', 'default-salt').encode('utf-8')
    
    # Create hash
    hash_obj = hashlib.sha256()
    hash_obj.update(salt)
    hash_obj.update(api_key.encode('utf-8'))
    
    hashed_key = hash_obj.hexdigest()
    logger.info("API key hashed successfully")
    return hashed_key


def verify_api_key(api_key, hashed_key):
    """
    Verify an API key against its hash.
    
    Args:
        api_key (str): The API key to verify
        hashed_key (str): The stored hash to verify against
        
    Returns:
        bool: True if the API key matches the hash
    """
    computed_hash = hash_api_key(api_key)
    is_valid = secrets.compare_digest(computed_hash, hashed_key)
    
    if is_valid:
        logger.info("API key verification successful")
    else:
        logger.warning("API key verification failed")
    
    return is_valid


def generate_jwt_signing_key():
    """
    Generate a unique JWT signing key for a client.
    
    Returns:
        str: PEM-encoded private key for JWT signing
    """
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Serialize to PEM format
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    signing_key = pem_private_key.decode('utf-8')
    logger.info("Generated JWT signing key")
    return signing_key


def get_public_key_from_private(private_key_pem):
    """
    Extract the public key from a private key for JWT verification.
    
    Args:
        private_key_pem (str): PEM-encoded private key
        
    Returns:
        str: PEM-encoded public key
    """
    # Load private key
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize to PEM format
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem_public_key.decode('utf-8')


def generate_client_credentials():
    """
    Generate a complete set of credentials for a new client.
    
    Returns:
        dict: Dictionary containing api_key, api_key_hash, and signing_key
    """
    # Generate API key
    api_key = generate_api_key()
    api_key_hash = hash_api_key(api_key)
    
    # Generate JWT signing key
    signing_key = generate_jwt_signing_key()
    
    credentials = {
        'api_key': api_key,
        'api_key_hash': api_key_hash,
        'signing_key': signing_key,
        'public_key': get_public_key_from_private(signing_key)
    }
    
    logger.info("Generated complete client credentials")
    return credentials


def rotate_client_credentials(current_signing_key=None):
    """
    Rotate client credentials while maintaining backward compatibility.
    
    Args:
        current_signing_key (str, optional): Current signing key to maintain for transition
        
    Returns:
        dict: New credentials with optional old signing key for transition period
    """
    # Generate new credentials
    new_credentials = generate_client_credentials()
    
    # If we have a current signing key, include it for transition
    if current_signing_key:
        new_credentials['old_signing_key'] = current_signing_key
        new_credentials['old_public_key'] = get_public_key_from_private(current_signing_key)
    
    logger.info("Rotated client credentials")
    return new_credentials


class ClientCredentialManager:
    """
    Manager class for handling client credential operations.
    """
    
    @staticmethod
    def create_client_credentials(client_name, client_type):
        """
        Create credentials for a new client with logging.
        
        Args:
            client_name (str): Name of the client
            client_type (str): Type of the client
            
        Returns:
            dict: Generated credentials
        """
        credentials = generate_client_credentials()
        
        logger.info(
            f"Created credentials for client '{client_name}' of type '{client_type}'"
        )
        
        return credentials
    
    @staticmethod
    def validate_client_credentials(client_id, api_key, stored_hash):
        """
        Validate client credentials with comprehensive logging.
        
        Args:
            client_id (str): Client ID
            api_key (str): Provided API key
            stored_hash (str): Stored hash to verify against
            
        Returns:
            bool: True if credentials are valid
        """
        is_valid = verify_api_key(api_key, stored_hash)
        
        if is_valid:
            logger.info(f"Client authentication successful for client_id: {client_id}")
        else:
            logger.warning(f"Client authentication failed for client_id: {client_id}")
        
        return is_valid
    
    @staticmethod
    def rotate_client_credentials_safe(client_id, current_signing_key):
        """
        Safely rotate client credentials with transition support.
        
        Args:
            client_id (str): Client ID
            current_signing_key (str): Current signing key
            
        Returns:
            dict: New credentials with transition support
        """
        new_credentials = rotate_client_credentials(current_signing_key)
        
        logger.info(f"Rotated credentials for client_id: {client_id}")
        
        return new_credentials


def generate_client_secret(client_id, client_type):
    """
    Generate a deterministic but secure client secret based on client info.
    This can be used for additional security layers.
    
    Args:
        client_id (str): Client ID
        client_type (str): Client type
        
    Returns:
        str: Generated client secret
    """
    # Create a deterministic but secure secret
    secret_input = f"{client_id}:{client_type}:{settings.SECRET_KEY}"
    
    hash_obj = hashlib.sha256()
    hash_obj.update(secret_input.encode('utf-8'))
    
    # Generate a base64-encoded secret
    secret = base64.urlsafe_b64encode(hash_obj.digest()).decode('utf-8')
    secret = secret.rstrip('=')  # Remove padding
    
    logger.info(f"Generated client secret for {client_type} client")
    return secret


def validate_client_secret(client_id, client_type, provided_secret):
    """
    Validate a client secret.
    
    Args:
        client_id (str): Client ID
        client_type (str): Client type
        provided_secret (str): Secret provided by client
        
    Returns:
        bool: True if secret is valid
    """
    expected_secret = generate_client_secret(client_id, client_type)
    is_valid = secrets.compare_digest(expected_secret, provided_secret)
    
    if is_valid:
        logger.info(f"Client secret validation successful for {client_id}")
    else:
        logger.warning(f"Client secret validation failed for {client_id}")
    
    return is_valid
