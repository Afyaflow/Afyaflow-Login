import graphene
from .types import UserType

class UserQuery(graphene.ObjectType):
    """GraphQL queries related to users."""
    me = graphene.Field(UserType, description="Returns the currently authenticated user's profile.")

    def resolve_me(self, info):
        user = info.context.user
        if user.is_anonymous:
            # In GraphQL, it's common to return null for unauthenticated users
            # or raise an exception that Graphene can handle as an error.
            # For now, let's return None, which will result in null in the GraphQL response.
            return None 
        return user
