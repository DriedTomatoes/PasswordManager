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

// Cache odszyfrowanych wpisów (klucz: id wpisu) - pozwala edycji odczytać aktualne dane
// bez ponownego deszyfrowania. Czyszczony przy wylogowaniu.
let vaultEntries = {};

// Funkcja pomocnicza do wyświetlania wiadomości
function showMessage(text, color) {
    statusText.innerText = text;
    statusText.style.color = color;
}

// Helper: pobierz token JWT z chrome.storage.session
async function getToken() {
    const s = await chrome.storage.session.get('jwtToken');
    return s.jwtToken;
}

// Helper: escape HTML, bo dane usera trafiaja do innerHTML
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// --- INICJALIZACJA PRZY OTWARCIU POPUPA ---
// Przywróć sesję z chrome.storage.session jeśli istnieje (user byl juz zalogowany)
async function initialize() {
    try {
        const session = await chrome.storage.session.get(['jwtToken', 'keyBytes']);
        if (session.jwtToken && session.keyBytes) {
            sessionEncryptionKey = await importKeyFromBase64(session.keyBytes);
            authArea.style.display = 'none';
            vaultArea.style.display = 'block';
            showMessage("", "black");
            loadVault();
        }
    } catch (err) {
        // Jesli odtworzenie klucza sie nie powiodlo, wyczysc sesje
        await chrome.storage.session.clear();
        showMessage("Sesja wygasła, zaloguj się ponownie.", "orange");
    }
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

        // 2. Wyliczenie klucza AUTORYZACYJNEGO (dla serwera)
        const authKeyHash = await deriveAuthKeyHash(password, saltData.salt);

        // 3. Wyliczenie klucza SZYFRUJĄCEGO AES-GCM (zostaje w pamieci wtyczki)
        sessionEncryptionKey = await deriveEncryptionKey(password, saltData.salt);

        // 4. Logowanie po token JWT
        const loginResponse = await fetch(`${API_URL}/login/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: email, auth_key_hash: authKeyHash })
        });

        if (!loginResponse.ok) throw new Error("Nieprawidłowe hasło.");

        const loginData = await loginResponse.json();

        // 5. Zapisanie JWT + zrzutu klucza do chrome.storage.session
        //    (session: zyje dopoki przegladarka jest otwarta, ginie na zamknieciu)
        const keyBytes = await exportKeyToBase64(sessionEncryptionKey);
        await chrome.storage.session.set({
            jwtToken: loginData.access,
            refreshToken: loginData.refresh,
            keyBytes: keyBytes
        });

        showMessage("Zalogowano pomyślnie!", "green");
        authArea.style.display = 'none';
        vaultArea.style.display = 'block';
        loadVault();
    } catch (error) {
        sessionEncryptionKey = null;
        showMessage("Błąd: " + error.message, "red");
    }
});

// --- OBSŁUGA WYLOGOWANIA ---
// Jawne wylogowanie - czyszczenie session storage + RAM popupa
document.getElementById('logoutBtn').addEventListener('click', async () => {
    await chrome.storage.session.clear();
    sessionEncryptionKey = null;
    vaultEntries = {};
    emailInput.value = '';
    passwordInput.value = '';
    document.getElementById('passwordList').innerHTML = '';
    authArea.style.display = 'block';
    vaultArea.style.display = 'none';
    showMessage("Wylogowano.", "black");
});

// --- DODANIE NOWEGO HASŁA ---
document.getElementById('savePasswordBtn').addEventListener('click', async () => {
    const url = document.getElementById('newUrl').value;
    const login = document.getElementById('newLogin').value;
    const pass = document.getElementById('newPassword').value;

    if (!url || !login || !pass) {
        return showMessage("Wypełnij wszystkie pola dla nowego wpisu!", "red");
    }
    if (!sessionEncryptionKey) {
        return showMessage("Brak klucza w pamięci. Zaloguj się ponownie.", "red");
    }

    showMessage("Szyfrowanie wpisu...", "black");

    try {
        const dataToEncrypt = JSON.stringify({ login: login, password: pass });
        const encrypted = await encryptData(sessionEncryptionKey, url, dataToEncrypt);

        const token = await getToken();
        if (!token) throw new Error("Brak tokenu JWT. Zaloguj się.");

        const response = await fetch(`${API_URL}/passwords/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
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
            document.getElementById('newUrl').value = '';
            document.getElementById('newLogin').value = '';
            document.getElementById('newPassword').value = '';
            loadVault();
        } else {
            throw new Error("Błąd zapisu na serwerze.");
        }
    } catch (error) {
        showMessage("Błąd dodawania hasła: " + error.message, "red");
    }
});

// --- USUWANIE WPISU ---
async function deleteEntry(id) {
    if (!confirm("Na pewno usunąć ten wpis?")) return;

    try {
        const token = await getToken();
        const response = await fetch(`${API_URL}/passwords/${id}/`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok || response.status === 204) {
            showMessage("Wpis usunięty.", "green");
            delete vaultEntries[id];
            loadVault();
        } else {
            throw new Error("Serwer odmówił usunięcia.");
        }
    } catch (error) {
        showMessage("Błąd usuwania: " + error.message, "red");
    }
}

// --- TRYB EDYCJI ---
// Pokazuje pola edycyjne pod widokiem wpisu
function showEditForm(li, id) {
    const entry = vaultEntries[id];
    if (!entry) return;

    // Nie otwieraj drugiej edycji jesli juz jest
    if (li.querySelector('.edit-form')) return;

    const form = document.createElement('div');
    form.className = 'edit-form';
    form.innerHTML = `
        <input type="text" class="edit-url" value="${escapeHtml(entry.url)}" placeholder="Strona">
        <input type="text" class="edit-login" value="${escapeHtml(entry.login)}" placeholder="Login">
        <input type="text" class="edit-password" value="${escapeHtml(entry.password)}" placeholder="Hasło">
        <div class="row">
            <button class="btn-save">Zapisz</button>
            <button class="btn-cancel">Anuluj</button>
        </div>
    `;
    li.appendChild(form);

    form.querySelector('.btn-save').addEventListener('click', () => {
        const newUrl = form.querySelector('.edit-url').value.trim();
        const newLogin = form.querySelector('.edit-login').value;
        const newPass = form.querySelector('.edit-password').value;
        if (!newUrl || !newLogin || !newPass) {
            return showMessage("Wypełnij wszystkie pola edycji!", "red");
        }
        saveEdit(id, newUrl, newLogin, newPass);
    });
    form.querySelector('.btn-cancel').addEventListener('click', () => form.remove());
}

// Zapisz zmiany - re-encrypt z (potencjalnie nowym) url i PUT na serwer
async function saveEdit(id, newUrl, newLogin, newPass) {
    if (!sessionEncryptionKey) {
        return showMessage("Brak klucza w pamięci. Zaloguj się ponownie.", "red");
    }
    showMessage("Aktualizowanie wpisu...", "black");

    try {
        const dataToEncrypt = JSON.stringify({ login: newLogin, password: newPass });
        const encrypted = await encryptData(sessionEncryptionKey, newUrl, dataToEncrypt);

        const token = await getToken();
        const response = await fetch(`${API_URL}/passwords/${id}/`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                url: newUrl,
                iv: encrypted.iv,
                ciphertext: encrypted.ciphertext,
                tag: 'wbudowany_w_ciphertext'
            })
        });

        if (response.ok) {
            showMessage("Wpis zaktualizowany.", "green");
            loadVault();
        } else {
            throw new Error("Błąd zapisu na serwerze.");
        }
    } catch (error) {
        showMessage("Błąd edycji: " + error.message, "red");
    }
}

// --- ŁADOWANIE I DESZYFROWANIE SEJFU ---
async function loadVault() {
    const listElement = document.getElementById('passwordList');
    if (!listElement) return;

    listElement.innerHTML = '<li>Pobieranie i deszyfrowanie haseł...</li>';
    vaultEntries = {};

    try {
        const token = await getToken();
        if (!token) throw new Error("Brak dostępu. Zaloguj się.");

        const response = await fetch(`${API_URL}/passwords/`, {
            method: 'GET',
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.status === 401) {
            await chrome.storage.session.clear();
            sessionEncryptionKey = null;
            authArea.style.display = 'block';
            vaultArea.style.display = 'none';
            listElement.innerHTML = '';
            throw new Error("Sesja wygasła. Zaloguj się ponownie.");
        }
        if (!response.ok) throw new Error("Błąd pobierania haseł z serwera.");

        const passwords = await response.json();
        listElement.innerHTML = '';

        if (passwords.length === 0) {
            listElement.innerHTML = '<li>Twój sejf jest pusty. Dodaj pierwsze hasło!</li>';
            return;
        }

        for (const item of passwords) {
            try {
                const decryptedString = await decryptData(
                    sessionEncryptionKey,
                    item.url,
                    item.iv,
                    item.ciphertext
                );
                const credentials = JSON.parse(decryptedString);

                // Cache do edycji
                vaultEntries[item.id] = {
                    url: item.url,
                    login: credentials.login,
                    password: credentials.password
                };

                const li = document.createElement('li');
                li.className = 'entry';
                li.dataset.id = item.id;
                li.innerHTML = `
                    <strong>🌍 ${escapeHtml(item.url)}</strong><br>
                    👤 Login: <code>${escapeHtml(credentials.login)}</code><br>
                    🔑 Hasło: <code>${escapeHtml(credentials.password)}</code>
                    <div class="entry-actions">
                        <button class="btn-edit">Edytuj</button>
                        <button class="btn-delete">Usuń</button>
                    </div>
                `;
                li.querySelector('.btn-edit').addEventListener('click', () => showEditForm(li, item.id));
                li.querySelector('.btn-delete').addEventListener('click', () => deleteEntry(item.id));
                listElement.appendChild(li);

            } catch (decErr) {
                console.error("Błąd deszyfrowania dla URL:", item.url, decErr);
                const li = document.createElement('li');
                li.style.color = "red";
                li.innerText = `❌ Nie udało się odszyfrować wpisu dla: ${item.url}`;
                listElement.appendChild(li);
            }
        }

    } catch (error) {
        listElement.innerHTML = `<li style="color:red;">Błąd: ${escapeHtml(error.message)}</li>`;
    }
}

// Start
initialize();
