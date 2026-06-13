from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

class CustomUserManager(BaseUserManager):
    def create_user(self, email, salt, auth_key_hash):
        if not email:
            raise ValueError("Użytkownik musi mieć adres email")
        user = self.model(
            email=self.normalize_email(email),
            salt=salt,
            auth_key_hash=auth_key_hash
        )
        user.save(using=self._db)
        return user

class CustomUser(AbstractBaseUser):
    email = models.EmailField(unique=True, max_length=255)
    
    # KRYPTOGRAFIA (Zamiast tradycyjnego hasła)
    salt = models.CharField(max_length=64) # Przechowujemy sól w Base64
    auth_key_hash = models.CharField(max_length=128) # Zhashowany na Kliencie Klucz B
    
    # USTAWIENIA 2FA
    is_2fa_active = models.BooleanField(default=False)
    totp_secret = models.CharField(max_length=32, blank=True, null=True)

    # Standardowe pola Django dla Usera
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['salt', 'auth_key_hash']

    def __str__(self):
        return self.email

    # Metody wymagane przez Django dla custom usera
    def has_perm(self, perm, obj=None): return True
    def has_module_perms(self, app_label): return True
    @property
    def is_staff(self): return self.is_admin


class LoginAttempt(models.Model):
    ip = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=['ip', 'timestamp'])]


class PasswordItem(models.Model):
    """ Model pojedynczego, zaszyfrowanego wpisu (Granularność) """
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='passwords')
    
    # AAD (Additional Authenticated Data) - jawny URL
    url = models.CharField(max_length=255) 
    
    # KRYPTOGRAFIA AES-GCM (Wszystko w Base64)
    iv = models.CharField(max_length=24)         # Wektor Inicjujący (zwykle 12 bajtów = 16 znaków Base64)
    ciphertext = models.TextField()              # Zaszyfrowany JSON z loginem i hasłem
    tag = models.CharField(max_length=32)        # Tag autentykacji (zwykle 16 bajtów = 24 znaki Base64)
    
    updated_at = models.DateTimeField(auto_now=True) # Zapobiega nadpisywaniu (Optimistic Locking)

    def __str__(self):
        return f"Zaszyfrowany wpis dla {self.url} (User: {self.user.email})"