from django.utils.functional import SimpleLazyObject
from .authentication import JWTAuthentication
from django.contrib.auth.models import AnonymousUser
from promise import Promise
import logging

logger = logging.getLogger(__name__)

class GraphQLJWTMiddleware:
    """
    Custom Django middleware to handle JWT-based authentication for the GraphQL endpoint.
    This version ensures the JWT-authenticated user is consistently used.
    """
    def __init__(self, get_response=None):
        self.get_response = get_response
        self.authenticator = JWTAuthentication()

    def __call__(self, request):
        request.user = SimpleLazyObject(lambda: self.get_user(request))
        return self.get_response(request)

    def get_user(self, request):
        auth_response = self.authenticator.authenticate(request)
        if auth_response:
            user, _ = auth_response
            return user
        return AnonymousUser()

    def resolve(self, next, root, info, **kwargs):
        context = info.context
        
        # Use a lazy object to avoid authenticating on every request
        # The user will only be fetched if it's accessed in a resolver
        context.user = SimpleLazyObject(lambda: self.get_user(context))

        return next(root, info, **kwargs) 