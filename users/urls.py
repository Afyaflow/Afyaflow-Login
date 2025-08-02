from django.urls import path, include
from .views import token_introspect, introspection_health

# Adding REST endpoints for specific auth flows alongside GraphQL
urlpatterns = [
    # Token introspection for service-to-service authentication
    path('auth/introspect/', token_introspect, name='token-introspect'),
    path('auth/introspect/health/', introspection_health, name='introspection-health'),

    # Existing allauth URLs
    path('accounts/', include('allauth.urls')),  # This includes all allauth URLs
]