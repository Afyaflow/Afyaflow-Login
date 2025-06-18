from users.authentication import JWTAuthentication

class GraphQLJWTMiddleware:
    """
    Custom Django middleware to handle JWT-based authentication for the GraphQL endpoint.
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.jwt_authenticator = JWTAuthentication()

    def __call__(self, request):
        # The GraphQLView, used for the /graphql endpoint, sets info.context 
        # to be the request object itself. By authenticating and attaching the 
        # user to the request here, it becomes available in all GraphQL resolvers 
        # as `info.context.user`.

        # Django's default AuthenticationMiddleware might have already attached a user 
        # from a session. For a stateless JWT API, we want to prioritize the token.
        auth_response = self.jwt_authenticator.authenticate(request)
        if auth_response:
            # If JWT authentication is successful, override request.user.
            request.user, _ = auth_response
        
        response = self.get_response(request)
        return response 