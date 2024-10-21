# users/urls.py
from django.urls import path
from .views import RegisterView, LoginView, GoogleLoginView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('loginG/', GoogleLoginView.as_view(), name='google-login'),
]
