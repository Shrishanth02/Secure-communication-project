"""Secure URL configuration."""
from django.urls import path, include

urlpatterns = [
    # The Django admin is intentionally not exposed (no admin app; custom user model).
    path('', include('SecureApp.urls')),
]
