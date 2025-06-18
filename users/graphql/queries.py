import graphene
from .types import UserType

class UserQuery(graphene.ObjectType):
    """GraphQL queries related to users."""
    me = graphene.Field(UserType)

    def resolve_me(root, info):
        user = info.context.user
        if user.is_authenticated:
            return user
        return None
