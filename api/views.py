import hmac
import hashlib
import base64
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from rest_framework import status, views, generics
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CustomUser, PasswordItem, LoginAttempt
from .serializers import RegisterSerializer, PasswordItemSerializer

# Ochrona przed brute-force: max 5 prób z jednego IP w oknie 5 minut
RATE_LIMIT = 5
RATE_WINDOW = timedelta(minutes=5)


def _check_rate_limit(ip):
    cutoff = timezone.now() - RATE_WINDOW
    LoginAttempt.objects.filter(timestamp__lt=cutoff).delete()
    return LoginAttempt.objects.filter(ip=ip, timestamp__gte=cutoff).count() >= RATE_LIMIT


def _fake_salt_for(email: str) -> str:
    # Deterministic fake salt derived from server secret + email.
    # Same email always produces the same value, so an attacker cannot
    # distinguish "user exists" from "user doesn't exist" by comparing
    # two responses for the same address.
    mac = hmac.new(settings.SECRET_KEY.encode(), email.lower().encode(), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode()


class RegisterView(views.APIView):
    # Wyjątek: Rejestracja musi być dostępna bez tokenu!
    permission_classes = [AllowAny] 

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Użytkownik zarejestrowany!"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class GetSaltView(views.APIView):
    # Wyjątek: Pobieranie soli musi być przed logowaniem
    permission_classes = [AllowAny] 

    def post(self, request):
        email = request.data.get('email', '')
        try:
            user = CustomUser.objects.get(email=email)
            salt = user.salt
        except CustomUser.DoesNotExist:
            # Return a fake but deterministic salt so the response is
            # indistinguishable from a real one — prevents user enumeration.
            salt = _fake_salt_for(email)
        return Response({"salt": salt}, status=status.HTTP_200_OK)


class CustomLoginView(views.APIView):
    # Wyjątek: Logowanie też omija globalną blokadę
    permission_classes = [AllowAny] 

    def post(self, request):
        email = request.data.get('email')
        auth_key_hash = request.data.get('auth_key_hash')

        if not email or not auth_key_hash:
            return Response({"error": "Brakuje emaila lub auth_key_hash."}, status=status.HTTP_400_BAD_REQUEST)

        ip = request.META.get('REMOTE_ADDR')
        if _check_rate_limit(ip):
            return Response(
                {"error": "Zbyt wiele prób logowania. Spróbuj ponownie za 5 minut."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            LoginAttempt.objects.create(ip=ip)
            return Response({"error": "Błędne dane logowania."}, status=status.HTTP_401_UNAUTHORIZED)

        # SPRAWDZENIE KRYPTOGRAFICZNE (Kluczowy moment Zero-Knowledge)
        if user.auth_key_hash != auth_key_hash:
            LoginAttempt.objects.create(ip=ip)
            return Response({"error": "Błędne dane logowania."}, status=status.HTTP_401_UNAUTHORIZED)

        # Jeśli hash się zgadza, generujemy tokeny JWT
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'message': 'Zalogowano pomyślnie!'
        }, status=status.HTTP_200_OK)


class PasswordListCreateView(generics.ListCreateAPIView):
    # Tutaj wymagamy, by użytkownik był zalogowany (musiał podać poprawny token JWT)
    permission_classes = [IsAuthenticated]
    serializer_class = PasswordItemSerializer

    # Zwracaj zawsze tylko hasła należące do zalogowanego usera!
    def get_queryset(self):
        return PasswordItem.objects.filter(user=self.request.user)

    # Przy tworzeniu nowego wpisu, przypisz go automatycznie do zalogowanego usera
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class PasswordDetailView(generics.RetrieveUpdateDestroyAPIView):
    """ GET / PUT / PATCH / DELETE pojedynczego wpisu po id.
        Filtrowanie po userze gwarantuje, ze user nie ruszy cudzych hasel. """
    permission_classes = [IsAuthenticated]
    serializer_class = PasswordItemSerializer

    def get_queryset(self):
        return PasswordItem.objects.filter(user=self.request.user)