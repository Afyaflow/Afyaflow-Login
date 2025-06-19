from django.urls import path
from .views import SocialLoginInitiateView, SocialLoginCallbackView

app_name = 'social_auth'

urlpatterns = [
    path('initiate/<str:provider>/', SocialLoginInitiateView.as_view(), name='initiate'),
    path('callback/<str:provider>/', SocialLoginCallbackView.as_view(), name='callback'),
] 