import graphene
import users.schema

class Query(users.schema.UserQuery, graphene.ObjectType):
    # This class will inherit from multiple Queries
    # as we add more apps to our project
    pass

class Mutation(users.schema.UserMutation, graphene.ObjectType):
    # This class will inherit from multiple Mutations
    # as we add more apps to our project
    pass

schema = graphene.Schema(query=Query, mutation=Mutation) 