// popup.js - Główna logika łączenia z serwerem

const API_URL = 'http://127.0.0.1:8000/api';

// Elementy UI
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const statusText = document.getElementById('status');
const authArea = document.getElementById('authArea');
const vaultArea = document.getElementById('vaultArea');

// ZMIENNA GLOBALNA: Przechowuje w pamięci RAM klucz do szyfrowania i deszyfrowania haseł
// (Nigdy nie zapisujemy go w localStorage ani nie wysyłamy na serwer!)
let sessionEncryptionKey = null; 

// Funkcja pomocnicza do wyświetlania wiadomości
function showMessage(text, color) {
    statusText.innerText = text;
    statusText.style.color = color;
}

// --- OBSŁUGA REJESTRACJI ---
document.getElementById('registerBtn').addEventListener('click', async () => {
    const email = emailInput.value;
    const password = passwordInput.value;

    if (!email || !password) return showMessage("Podaj email i hasło!", "red");

    showMessage("Generowanie kluczy i rejestracja...", "black");

    try {
        const salt = generateSalt();
        const authKeyHash = await deriveAuthKeyHash(password, salt);

        const response = await fetch(`${API_URL}/register/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email, salt: salt, auth_key_hash: authKeyHash })
        });

        if (response.ok) {
            showMessage("Konto założone! Możesz się zalogować.", "green");
        } else {
            showMessage("Błąd rejestracji. Taki email już istnieje.", "red");
        }
    } catch (error) {
        showMessage("Błąd połączenia: " + error.message, "red");
    }
});

// --- OBSŁUGA LOGOWANIA ---
document.getElementById('loginBtn').addEventListener('click', async () => {
    const email = emailInput.value;
    const password = passwordInput.value;

    if (!email || !password) return showMessage("Podaj email i hasło!", "red");

    showMessage("Logowanie...", "black");

    try {
        // 1. Prośba o sól
        const saltResponse = await fetch(`${API_URL}/get-salt/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email })
        });

        if (!saltResponse.ok) throw new Error("Nie znaleziono użytkownika.");

        const saltData = await saltResponse.json();
        
        // 2. Wyliczenie klucza AUTORYZACYJNEGO (Dla serwera)
        const authKeyHash = await deriveAuthKeyHash(password, saltData.salt);

        // 3. Wyliczenie klucza SZYFRUJĄCEGO AES-GCM (Zostaje w pamięci wtyczki!)
        sessionEncryptionKey = await deriveEncryptionKey(password, saltData.salt);

        // 4. Logowanie po token JWT
        const loginResponse = await fetch(`${API_URL}/login/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email, auth_key_hash: authKeyHash })
        });

        if (loginResponse.ok) {
            const loginData = await loginResponse.json();
            
            // Zapisanie JWT do pamięci przeglądarki
            chrome.storage.local.set({ 'jwtToken': loginData.access }, () => {
                showMessage("Zalogowano pomyślnie!", "green");
                
                // PRZEŁĄCZANIE INTERFEJSU
                authArea.style.display = 'none';
                vaultArea.style.display = 'block';
                
                loadVault(); 
            });
        } else {
            throw new Error("Nieprawidłowe hasło.");
        }
    } catch (error) {
        showMessage("Błąd: " + error.message, "red");
    }
});

// --- OBSŁUGA WYLOGOWANIA (Wyczyszczenie pamięci RAM i tokenów) ---
document.getElementById('logoutBtn').addEventListener('click', () => {
    chrome.storage.local.remove('jwtToken', () => {
        sessionEncryptionKey = null; // Bardzo ważne! Czyścimy klucz z pamięci RAM
        emailInput.value = '';
        passwordInput.value = '';
        authArea.style.display = 'block';
        vaultArea.style.display = 'none';
        showMessage("Wylogowano.", "black");
    });
});

// --- OBSŁUGA DODAWANIA NOWEGO HASŁA DO SEJFU ---
document.getElementById('savePasswordBtn').addEventListener('click', async () => {
    const url = document.getElementById('newUrl').value;
    const login = document.getElementById('newLogin').value;
    const pass = document.getElementById('newPassword').value;

    if (!url || !login || !pass) {
        return showMessage("Wypełnij wszystkie pola dla nowego wpisu!", "red");
    }

    if (!sessionEncryptionKey) {
        return showMessage("Błąd krytyczny: Brak klucza szyfrującego w pamięci RAM!", "red");
    }

    showMessage("Szyfrowanie wpisu...", "black");

    try {
        // 1. Złożenie loginu i hasła w jeden obiekt i zamiana na ciąg znaków JSON
        const dataToEncrypt = JSON.stringify({ login: login, password: pass });

        // 2. Szyfrowanie po stronie klienta (Klucz + URL jako dane dodatkowe)
        const encrypted = await encryptData(sessionEncryptionKey, url, dataToEncrypt);

        // UWAGA: WebCrypto API (AES-GCM) dokleja tzw. tag autentykacyjny na sam koniec ciphertextu. 
        // Skoro na backendzie masz osobne pole 'tag' o stałej długości, wpisujemy w nie cokolwiek 
        // lub modyfikujemy backend. Na ten moment wyślemy znacznik "wbudowany".
        
        // 3. Pobranie tokenu autoryzacyjnego JWT z pamięci przeglądarki
        const storage = await chrome.storage.local.get('jwtToken');
        if (!storage.jwtToken) throw new Error("Brak tokenu JWT. Zaloguj się.");

        // 4. Wysłanie ZASZYFROWANYCH danych na serwer
        const response = await fetch(`${API_URL}/passwords/`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${storage.jwtToken}` // <--- Ważne! Token JWT
            },
            body: JSON.stringify({
                url: url,
                iv: encrypted.iv,
                ciphertext: encrypted.ciphertext,
                tag: 'wbudowany_w_ciphertext' 
            })
        });

        if (response.ok) {
            showMessage("Pomyślnie dodano hasło do sejfu!", "green");
            // Czyszczenie pól
            document.getElementById('newUrl').value = '';
            document.getElementById('newLogin').value = '';
            document.getElementById('newPassword').value = '';

            loadVault();
            
            // W tym miejscu w przyszłości przeładujemy listę zapisanych haseł
        } else {
            throw new Error("Błąd zapisu na serwerze.");
        }
    } catch (error) {
        showMessage("Błąd dodawania hasła: " + error.message, "red");
    }
});

// --- OBSŁUGA ŁADOWANIA SEJFU (Pobieranie i deszyfrowanie) ---
async function loadVault() {
    const listElement = document.getElementById('passwordList');
    if (!listElement) return; // Zabezpieczenie, jeśli UI nie jest gotowe
    
    listElement.innerHTML = '<li>Pobieranie i deszyfrowanie haseł...</li>';

    try {
        const storage = await chrome.storage.local.get('jwtToken');
        if (!storage.jwtToken) throw new Error("Brak dostępu. Zaloguj się.");

        // 1. Pobieranie ZASZYFROWANYCH danych z backendu (Django)
        const response = await fetch(`${API_URL}/passwords/`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${storage.jwtToken}`
            }
        });

        if (!response.ok) throw new Error("Błąd pobierania haseł z serwera.");

        const passwords = await response.json();
        listElement.innerHTML = ''; // Czyścimy listę "ładowania"

        if (passwords.length === 0) {
            listElement.innerHTML = '<li>Twój sejf jest pusty. Dodaj pierwsze hasło!</li>';
            return;
        }

        // 2. Przechodzimy przez każde hasło i odszyfrowujemy je w pamięci przeglądarki
        for (const item of passwords) {
            try {
                // To tutaj dzieje się magia Zero-Knowledge:
                const decryptedString = await decryptData(
                    sessionEncryptionKey, 
                    item.url, 
                    item.iv, 
                    item.ciphertext
                );
                
                // Zamieniamy odkodowany ciąg tekstowy z powrotem na obiekt JSON
                const credentials = JSON.parse(decryptedString);

                // 3. Budujemy element listy (HTML) z odszyfrowanymi danymi
                const li = document.createElement('li');
                li.style.marginBottom = "10px";
                li.style.padding = "10px";
                li.style.border = "1px solid #ccc";
                li.style.borderRadius = "5px";
                li.style.backgroundColor = "#f9f9f9";
                
                li.innerHTML = `
                    <strong>🌍 ${item.url}</strong><br>
                    👤 Login: <code>${credentials.login}</code><br>
                    🔑 Hasło: <code>${credentials.password}</code>
                `;
                listElement.appendChild(li);

            } catch (decErr) {
                // Jeśli klucz jest zły (np. ktoś podmienił bazę) lub dane uszkodzone
                console.error("Błąd deszyfrowania dla URL:", item.url, decErr);
                const li = document.createElement('li');
                li.style.color = "red";
                li.innerText = `❌ Nie udało się odszyfrować wpisu dla: ${item.url}`;
                listElement.appendChild(li);
            }
        }

    } catch (error) {
        listElement.innerHTML = `<li style="color:red;">Błąd: ${error.message}</li>`;
    }
}