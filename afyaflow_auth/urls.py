from django.contrib import admin
from django.urls import path, include
from graphene_django.views import GraphQLView
from django.views.decorators.csrf import csrf_exempt # Only if you need to disable CSRF for GraphQL

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('users.urls')),  # Enabled for Google OAuth callback
    path("graphql", csrf_exempt(GraphQLView.as_view(graphiql=True))), # Using csrf_exempt for testing
    # path("graphql", GraphQLView.as_view(graphiql=True)), # graphiql=True enables the in-browser IDE
    path('accounts/', include('allauth.urls')), # Added for django-allauth
] 