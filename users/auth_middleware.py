from users.authentication import JWTAuthentication

class GraphQLJWTMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # We only want to apply this to the GraphQL endpoint
        if request.path == '/graphql' or request.path == '/graphql/':
            print(f"[GraphQL Middleware] Path: {request.path}") # Debug print
            auth_header_value = request.headers.get('Authorization')
            print(f"[GraphQL Middleware] Authorization Header: '{auth_header_value}'") # Debug print
            
            if not auth_header_value: # Explicitly check if header is missing before JWTAuthentication
                print("[GraphQL Middleware] Authorization Header is missing or empty.")
            else:
                auth = JWTAuthentication()
                try:
                    # Attempt to authenticate the user using the JWTAuthentication class
                    user_auth_tuple = auth.authenticate(request)
                    if user_auth_tuple is not None:
                        request.user = user_auth_tuple[0]
                        request.auth = user_auth_tuple[1]
                        print(f"[GraphQL Middleware] User authenticated: {request.user}") # Debug print
                    else:
                        # If authentication fails or no token, request.user remains AnonymousUser
                        print("[GraphQL Middleware] JWTAuthentication.authenticate returned None.")
                        pass
                except Exception as e:
                    # Handle potential exceptions from authenticate
                    print(f"[GraphQL Middleware] JWTAuthentication Error: {e}") # Changed error prefix
                    pass # Ensure request continues

        response = self.get_response(request)
        return response 