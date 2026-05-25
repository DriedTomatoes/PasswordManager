from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import RegisterView, CustomLoginView, GetSaltView, PasswordListCreateView, PasswordDetailView

urlpatterns = [
    # Adres dla wtyczki do rejestracji nowych użytkowników
    path('register/', RegisterView.as_view(), name='register'),
    
    # 2-etapowe logowanie Zero-Knowledge
    path('get-salt/', GetSaltView.as_view(), name='get_salt'),
    path('login/', CustomLoginView.as_view(), name='custom_login'),
    
    # Odświeżanie tokenu (zostawiamy standardowe z biblioteki)
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('passwords/', PasswordListCreateView.as_view(), name='password_list_create'),
    path('passwords/<int:pk>/', PasswordDetailView.as_view(), name='password_detail'),
]