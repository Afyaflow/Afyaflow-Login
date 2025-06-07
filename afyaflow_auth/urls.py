# project/urls.py (or wherever your main urlpatterns are defined)

from django.contrib import admin
from django.urls import path, include
from graphene_django.views import GraphQLView
from django.views.decorators.csrf import csrf_exempt

# Import your federated schema
# Adjust 'users.schema' to the actual Python path of your schema file and variable
from users.graphql.schema import schema as users_federated_schema # Renaming to avoid potential name clashes

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('users.urls')),  # For Google OAuth callback etc.
    path('accounts/', include('allauth.urls')), # For django-allauth

    # Your primary GraphQL endpoint using the federated schema
    path("graphql", csrf_exempt(GraphQLView.as_view(
        graphiql=True,
        schema=users_federated_schema # Pass your federated schema here
    ))),
]