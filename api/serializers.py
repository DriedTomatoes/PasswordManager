from rest_framework import serializers
from .models import CustomUser, PasswordItem

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        # Te trzy pola wtyczka musi przysłać podczas rejestracji
        fields = ('email', 'salt', 'auth_key_hash')

    def create(self, validated_data):
        # Używamy Waszego CustomUserManager z models.py
        user = CustomUser.objects.create_user(
            email=validated_data['email'],
            salt=validated_data['salt'],
            auth_key_hash=validated_data['auth_key_hash']
        )
        return user
    
from .models import PasswordItem

class PasswordItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordItem
        # Pola, które klient wysyła lub pobiera:
        fields = ['id', 'url', 'iv', 'ciphertext', 'tag', 'updated_at']
        read_only_fields = ['id', 'updated_at']