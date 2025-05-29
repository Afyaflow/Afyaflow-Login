from django.urls import path
#from .views import GoogleLoginView, LogoutView

# Adding REST endpoints for specific auth flows alongside GraphQL
urlpatterns = [
    #path('auth/google/', GoogleLoginView.as_view(), name='google-login'),
    #path('auth/logout/', LogoutView.as_view(), name='logout'),
] 