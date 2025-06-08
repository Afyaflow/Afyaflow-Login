# project/urls.py (or wherever your main urlpatterns are defined)

from django.contrib import admin
from django.urls import path, include
from graphene_django.views import GraphQLView
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from django.conf import settings

# Import federated schema
from users.graphql.schema import schema as users_federated_schema # Renaming to avoid potential name clashes

# Simple health check view
def health_check(request):
    return HttpResponse("OK", content_type="text/plain")

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('users.urls')),  # For Google OAuth callback etc.
    path('accounts/', include('allauth.urls')), # For django-allauth
    
    # Health check endpoint for Railway
    path('health/', health_check),

    # Your primary GraphQL endpoint using the federated schema
    path("graphql", csrf_exempt(GraphQLView.as_view(
        graphiql=settings.DEBUG, # Set to True in dev, False in prod
        schema=users_federated_schema # Pass your federated schema here
    ))),
]