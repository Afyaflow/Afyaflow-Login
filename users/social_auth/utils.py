import base64
import hashlib
import os
import secrets

class PKCEManager:
    """
    Manages Proof Key for Code Exchange (PKCE) parameter generation.
    PKCE is a security extension to the OAuth 2.0 authorization code flow
    that prevents authorization code interception attacks.
    """
    @staticmethod
    def generate_code_verifier() -> str:
        """
        Generate a cryptographically random string to be used as the code verifier.
        The verifier is a high-entropy string between 43 and 128 characters long.
        """
        return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')

    @staticmethod
    def generate_code_challenge(verifier: str) -> str:
        """
        Generate a code challenge from the provided verifier using SHA256 hashing.
        The challenge is sent to the authorization server, and the verifier is sent
        to the token endpoint to prove the client's identity.
        """
        digest = hashlib.sha256(verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')

class StateManager:
    """
    Manages the 'state' parameter used to prevent Cross-Site Request Forgery (CSRF) attacks.
    """
    @staticmethod
    def generate_state() -> str:
        """
        Generate a cryptographically secure random string to be used as the state parameter.
        This value is sent to the authorization server and should be returned unchanged.
        """
        return secrets.token_urlsafe(32)

    @staticmethod
    def validate_state(session_state: str, received_state: str) -> bool:
        """
        Securely compare the state value stored in the session with the one received
        from the authorization server to ensure they match.
        """
        if not session_state or not received_state:
            return False
        return secrets.compare_digest(session_state, received_state) 