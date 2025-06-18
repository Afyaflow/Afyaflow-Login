from users.authentication import JWTAuthentication
from django.contrib.auth.models import AnonymousUser
import logging

logger = logging.getLogger(__name__)

class GraphQLJWTMiddleware:
    """
    Custom Django middleware to handle JWT-based authentication for the GraphQL endpoint.
    This version ensures the JWT-authenticated user is consistently used.
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.jwt_authenticator = JWTAuthentication()

    def __call__(self, request):
        # By default, request.user is an AnonymousUser.
        # Django's standard AuthenticationMiddleware might run and attach a 
        # session-based user. We want our JWT user to be definitive.
        
        # We wrap the authentication in a property on the request itself.
        # This is a robust pattern used by libraries like Django Rest Framework.
        # It defers authentication until `request.user` is accessed.
        request.user = self.LazyUser(self.jwt_authenticator, request)
        
        response = self.get_response(request)
        return response

    class LazyUser:
        def __init__(self, authenticator, request):
            self._authenticator = authenticator
            self._request = request
            self._user = None

        def __get__(self, request, obj_type=None):
            if self._user is None:
                auth_response = self._authenticator.authenticate(self._request)
                if auth_response:
                    self._user = auth_response[0]
                else:
                    self._user = AnonymousUser()
            return self._user 