from rest_framework import status, views, generics
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CustomUser, PasswordItem
from .serializers import RegisterSerializer, PasswordItemSerializer


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
        email = request.data.get('email')
        try:
            user = CustomUser.objects.get(email=email)
            # Wtyczka potrzebuje soli do wyliczenia kluczy
            return Response({"salt": user.salt}, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({"error": "Użytkownik nie istnieje."}, status=status.HTTP_404_NOT_FOUND)


class CustomLoginView(views.APIView):
    # Wyjątek: Logowanie też omija globalną blokadę
    permission_classes = [AllowAny] 

    def post(self, request):
        email = request.data.get('email')
        auth_key_hash = request.data.get('auth_key_hash')

        if not email or not auth_key_hash:
            return Response({"error": "Brakuje emaila lub auth_key_hash."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({"error": "Błędne dane logowania."}, status=status.HTTP_401_UNAUTHORIZED)

        # SPRAWDZENIE KRYPTOGRAFICZNE (Kluczowy moment Zero-Knowledge)
        if user.auth_key_hash != auth_key_hash:
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