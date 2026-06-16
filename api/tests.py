"""
Testy bezpieczeństwa PasswordManager

Uruchomienie:
    source venv/bin/activate
    python manage.py test api.tests -v 2
"""
import unittest
from django.test import TestCase
from rest_framework_simplejwt.tokens import RefreshToken
from . import models as _m
from .models import CustomUser, PasswordItem

HAS_RATE_LIMITING = hasattr(_m, 'LoginAttempt')


class UserEnumerationTests(TestCase):
    """
    Weryfikuje czy /api/get-salt/ ujawnia istnienie konta po kodzie odpowiedzi.
    """

    def setUp(self):
        CustomUser.objects.create_user(
            email='istniejacy@test.pl',
            salt='dGVzdHNhbHQ=',
            auth_key_hash='dGVzdGhhc2g='
        )

    def test_istniejacy_uzytkownik_zwraca_200(self):
        r = self.client.post('/api/get-salt/',
            {'email': 'istniejacy@test.pl'},
            content_type='application/json')
        self.assertEqual(r.status_code, 200)

    def test_nieistniejacy_uzytkownik_zwraca_200(self):
        r = self.client.post('/api/get-salt/',
            {'email': 'nieistniejacy@test.pl'},
            content_type='application/json')
        self.assertEqual(r.status_code, 200)

    def test_fake_sol_jest_deterministyczna(self):
        # Ten sam nieistniejący email musi zawsze dawać tę samą sól
        r1 = self.client.post('/api/get-salt/',
            {'email': 'ghost@test.pl'},
            content_type='application/json')
        r2 = self.client.post('/api/get-salt/',
            {'email': 'ghost@test.pl'},
            content_type='application/json')
        self.assertEqual(r1.json().get('salt'), r2.json().get('salt'))


@unittest.skipUnless(HAS_RATE_LIMITING, "Brak modelu LoginAttempt")
class BruteForceTests(TestCase):
    """
    Weryfikuje ochronę przed atakiem brute-force na /api/login/.
    """

    def setUp(self):
        CustomUser.objects.create_user(
            email='cel@test.pl',
            salt='dGVzdHNhbHQ=',
            auth_key_hash='poprawnyHash123'
        )

    def _login(self, auth_key_hash='zlyHash', ip='127.0.0.1'):
        return self.client.post('/api/login/',
            {'email': 'cel@test.pl', 'auth_key_hash': auth_key_hash},
            content_type='application/json',
            REMOTE_ADDR=ip)

    def test_poprawne_logowanie_dziala_przed_limitem(self):
        r = self._login('poprawnyHash123')
        self.assertEqual(r.status_code, 200)

    def test_blokada_po_5_blednych_probach(self):
        for _ in range(5):
            self._login('zlyHash')
        r = self._login('zlyHash')
        self.assertEqual(r.status_code, 429)

    def test_poprawne_haslo_blokowane_gdy_ip_zablokowane(self):
        for _ in range(5):
            self._login('zlyHash')
        r = self._login('poprawnyHash123')
        self.assertEqual(r.status_code, 429)

    def test_blokada_po_ataku_z_roznych_ip_na_ten_sam_email(self):
        # Botnet z różnych IP atakujący jedno konto — blokada przez licznik emaila
        for i in range(5):
            self.client.post('/api/login/',
                {'email': 'cel@test.pl', 'auth_key_hash': 'zlyHash'},
                content_type='application/json',
                REMOTE_ADDR=f'10.0.0.{i+1}')
        r = self.client.post('/api/login/',
            {'email': 'cel@test.pl', 'auth_key_hash': 'zlyHash'},
            content_type='application/json',
            REMOTE_ADDR='10.0.0.99')
        self.assertEqual(r.status_code, 429)

    def test_blokada_jednego_ip_atakujacego_rozne_emaile(self):
        # Jeden IP próbuje różnych emaili — blokada przez licznik IP
        for i in range(5):
            self.client.post('/api/login/',
                {'email': f'ofiara{i}@test.pl', 'auth_key_hash': 'zlyHash'},
                content_type='application/json',
                REMOTE_ADDR='5.5.5.5')
        r = self.client.post('/api/login/',
            {'email': 'kolejna@test.pl', 'auth_key_hash': 'zlyHash'},
            content_type='application/json',
            REMOTE_ADDR='5.5.5.5')
        self.assertEqual(r.status_code, 429)


class AuthenticationTests(TestCase):
    """
    Weryfikuje czy endpointy wymagają tokenu JWT.
    """

    def test_lista_hasel_wymaga_tokenu(self):
        r = self.client.get('/api/passwords/')
        self.assertEqual(r.status_code, 401)

    def test_szczegoly_hasla_wymagaja_tokenu(self):
        r = self.client.get('/api/passwords/1/')
        self.assertEqual(r.status_code, 401)

    def test_usuwanie_hasla_wymaga_tokenu(self):
        r = self.client.delete('/api/passwords/1/')
        self.assertEqual(r.status_code, 401)

    def test_edycja_hasla_wymaga_tokenu(self):
        r = self.client.put('/api/passwords/1/',
            {'url': 'x', 'iv': 'x', 'ciphertext': 'x', 'tag': 'x'},
            content_type='application/json')
        self.assertEqual(r.status_code, 401)


class IDORTests(TestCase):
    """
    Testuje czy użytkownik A może uzyskać dostęp do haseł użytkownika B.
    """

    def setUp(self):
        self.user_a = CustomUser.objects.create_user(
            email='a@test.pl', salt='saltA', auth_key_hash='hashA'
        )
        self.user_b = CustomUser.objects.create_user(
            email='b@test.pl', salt='saltB', auth_key_hash='hashB'
        )
        self.wpis_b = PasswordItem.objects.create(
            user=self.user_b,
            url='https://przyklad.pl',
            iv='testIV123456',
            ciphertext='zaszyfrowaneDane',
            tag='testTag'
        )

    def _token(self, user):
        return str(RefreshToken.for_user(user).access_token)

    def test_user_a_nie_widzi_hasel_user_b(self):
        r = self.client.get(
            f'/api/passwords/{self.wpis_b.id}/',
            HTTP_AUTHORIZATION=f'Bearer {self._token(self.user_a)}'
        )
        self.assertEqual(r.status_code, 404)

    def test_user_a_nie_moze_usunac_hasel_user_b(self):
        r = self.client.delete(
            f'/api/passwords/{self.wpis_b.id}/',
            HTTP_AUTHORIZATION=f'Bearer {self._token(self.user_a)}'
        )
        self.assertEqual(r.status_code, 404)

    def test_user_b_widzi_wlasne_hasla(self):
        r = self.client.get(
            f'/api/passwords/{self.wpis_b.id}/',
            HTTP_AUTHORIZATION=f'Bearer {self._token(self.user_b)}'
        )
        self.assertEqual(r.status_code, 200)

    def test_user_b_moze_usunac_wlasne_haslo(self):
        r = self.client.delete(
            f'/api/passwords/{self.wpis_b.id}/',
            HTTP_AUTHORIZATION=f'Bearer {self._token(self.user_b)}'
        )
        self.assertEqual(r.status_code, 204)
