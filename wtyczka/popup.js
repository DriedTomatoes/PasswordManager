// popup.js - Główny kontroler aplikacji
import * as api from './api.js';
import * as ui from './ui.js';
import { triggerAutofillToActiveTab, listenForAutofillRequests } from './autofill-service.js';

// Elementy UI
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const authArea = document.getElementById('authArea');
const vaultArea = document.getElementById('vaultArea');
const listElement = document.getElementById('passwordList');

// Stan aplikacji (In-memory)
let sessionEncryptionKey = null;
let vaultEntries = {};

// Inicjalizacja przy otwarciu popupa
async function initialize() {
    try {
        const session = await chrome.storage.session.get(['jwtToken', 'keyBytes']);
        if (session.jwtToken && session.keyBytes) {
            sessionEncryptionKey = await importKeyFromBase64(session.keyBytes);
            authArea.style.display = 'none';
            vaultArea.style.display = 'block';
            ui.showMessage("", "black");
            loadVault();
        }
    } catch (err) {
        await chrome.storage.session.clear();
        ui.showMessage("Sesja wygasła, zaloguj się ponownie.", "orange");
    }
}

// Obsługa Rejestracji
document.getElementById('registerBtn').addEventListener('click', async () => {
    const email = emailInput.value;
    const password = passwordInput.value;
    if (!email || !password) return ui.showMessage("Podaj email i hasło!", "red");

    ui.showMessage("Generowanie kluczy i rejestracja...", "black");
    try {
        const salt = generateSalt();
        const authKeyHash = await deriveAuthKeyHash(password, salt);
        const response = await api.registerUser(email, salt, authKeyHash);

        if (response.ok) ui.showMessage("Konto założone! Możesz się zalogować.", "green");
        else ui.showMessage("Błąd rejestracji. Taki email już istnieje.", "red");
    } catch (error) {
        ui.showMessage("Błąd połączenia: " + error.message, "red");
    }
});

// Obsługa Logowania
document.getElementById('loginBtn').addEventListener('click', async () => {
    const email = emailInput.value;
    const password = passwordInput.value;
    if (!email || !password) return ui.showMessage("Podaj email i hasło!", "red");

    ui.showMessage("Logowanie...", "black");
    try {
        const saltData = await api.fetchSalt(email);
        const authKeyHash = await deriveAuthKeyHash(password, saltData.salt);
        sessionEncryptionKey = await deriveEncryptionKey(password, saltData.salt);

        const loginData = await api.loginUser(email, authKeyHash);
        const keyBytes = await exportKeyToBase64(sessionEncryptionKey);
        
        await chrome.storage.session.set({
            jwtToken: loginData.access,
            refreshToken: loginData.refresh,
            keyBytes: keyBytes
        });

        ui.showMessage("Zalogowano pomyślnie!", "green");
        authArea.style.display = 'none';
        vaultArea.style.display = 'block';
        loadVault();
    } catch (error) {
        sessionEncryptionKey = null;
        ui.showMessage("Błąd: " + error.message, "red");
    }
});

// Obsługa Wylogowania
document.getElementById('logoutBtn').addEventListener('click', async () => {
    await chrome.storage.session.clear();
    sessionEncryptionKey = null;
    vaultEntries = {};
    emailInput.value = '';
    passwordInput.value = '';
    listElement.innerHTML = '';
    authArea.style.display = 'block';
    vaultArea.style.display = 'none';
    ui.showMessage("Wylogowano.", "black");
});

// Dodanie nowego hasła
document.getElementById('savePasswordBtn').addEventListener('click', async () => {
    const url = document.getElementById('newUrl').value;
    const login = document.getElementById('newLogin').value;
    const pass = document.getElementById('newPassword').value;

    if (!url || !login || !pass) return ui.showMessage("Wypełnij wszystkie pola dla nowego wpisu!", "red");
    if (!sessionEncryptionKey) return ui.showMessage("Brak klucza w pamięci. Zaloguj się ponownie.", "red");

    ui.showMessage("Szyfrowanie wpisu...", "black");
    try {
        const dataToEncrypt = JSON.stringify({ login, password: pass });
        const encrypted = await encryptData(sessionEncryptionKey, url, dataToEncrypt);
        const response = await api.sendEncryptedPassword(url, encrypted);

        if (response.ok) {
            ui.showMessage("Pomyślnie dodano hasło do sejfu!", "green");
            document.getElementById('newUrl').value = '';
            document.getElementById('newLogin').value = '';
            document.getElementById('newPassword').value = '';
            loadVault();
        } else {
            throw new Error("Błąd zapisu na serwerze.");
        }
    } catch (error) {
        ui.showMessage("Błąd dodawania hasła: " + error.message, "red");
    }
});

// Ładowanie i deszyfrowanie sejfu
async function loadVault() {
    if (!listElement) return;
    listElement.innerHTML = '<li>Pobieranie i deszyfrowanie haseł...</li>';
    vaultEntries = {};

    try {
        const response = await api.fetchAllPasswords();
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
                const decryptedString = await decryptData(sessionEncryptionKey, item.url, item.iv, item.ciphertext);
                const credentials = JSON.parse(decryptedString);

                vaultEntries[item.id] = { url: item.url, login: credentials.login, password: credentials.password };

                const li = ui.createEntryTemplate(item, credentials);
                li.querySelector('.btn-edit').addEventListener('click', () => showEditForm(li, item.id));
                li.querySelector('.btn-delete').addEventListener('click', () => deleteEntry(item.id));
                listElement.appendChild(li);
            } catch (decErr) {
                const li = document.createElement('li');
                li.style.color = "red";
                li.innerText = `Nie udało się odszyfrować wpisu dla: ${item.url}`;
                listElement.appendChild(li);
            }
        }
        triggerAutofillToActiveTab(vaultEntries);
    } catch (error) {
        listElement.innerHTML = `<li style="color:red;">Błąd: ${ui.escapeHtml(error.message)}</li>`;
    }
}

// Usuwanie wpisu
async function deleteEntry(id) {
    if (!confirm("Na pewno usunąć ten wpis?")) return;
    try {
        const response = await api.deletePasswordEntry(id);
        if (response.ok || response.status === 204) {
            ui.showMessage("Wpis usunięty.", "green");
            delete vaultEntries[id];
            loadVault();
        } else {
            throw new Error("Serwer odmówił usunięcia.");
        }
    } catch (error) {
        ui.showMessage("Błąd usuwania: " + error.message, "red");
    }
}

// Pokazywanie formularza edycji
function showEditForm(li, id) {
    const entry = vaultEntries[id];
    if (!entry || li.querySelector('.edit-form')) return;

    const form = ui.appendEditForm(li, entry);
    form.querySelector('.btn-save').addEventListener('click', () => {
        const newUrl = form.querySelector('.edit-url').value.trim();
        const newLogin = form.querySelector('.edit-login').value;
        const newPass = form.querySelector('.edit-password').value;
        if (!newUrl || !newLogin || !newPass) return ui.showMessage("Wypełnij wszystkie pola edycji!", "red");
        saveEdit(id, newUrl, newLogin, newPass);
    });
    form.querySelector('.btn-cancel').addEventListener('click', () => form.remove());
}

// Zapisywanie edycji
async function saveEdit(id, newUrl, newLogin, newPass) {
    if (!sessionEncryptionKey) return ui.showMessage("Brak klucza w pamięci. Zaloguj się ponownie.", "red");
    ui.showMessage("Aktualizowanie wpisu...", "black");

    try {
        const dataToEncrypt = JSON.stringify({ login: newLogin, password: newPass });
        const encrypted = await encryptData(sessionEncryptionKey, newUrl, dataToEncrypt);
        const response = await api.updateEncryptedPassword(id, newUrl, encrypted);

        if (response.ok) {
            ui.showMessage("Wpis zaktualizowany.", "green");
            loadVault();
        } else {
            throw new Error("Błąd zapisu na serwerze.");
        }
    } catch (error) {
        ui.showMessage("Błąd edycji: " + error.message, "red");
    }
}

// Globalne nasłuchiwanie zdarzeń (Oko i Kopiowanie)
document.addEventListener('click', async function(event) {
    const target = event.target;

    // Logika oka
    if (target.classList.contains('toggle-password-btn')) {
        const targetId = target.getAttribute('data-target');
        const passwordCode = document.getElementById(targetId);
        if (!passwordCode) return;
        const realPassword = passwordCode.getAttribute('data-password');

        if (passwordCode.classList.contains('masked')) {
            passwordCode.innerText = realPassword;
            passwordCode.classList.remove('masked');
            target.innerText = '🔒';
        } else {
            passwordCode.innerText = '••••••••';
            passwordCode.classList.add('masked');
            target.innerText = '👀';
        }
    }

    // Kopiowanie Loginu
    if (target.classList.contains('login-text')) {
        const textToCopy = target.getAttribute('data-login');
        const originalText = target.innerHTML;
        try {
            await navigator.clipboard.writeText(textToCopy);
            target.innerHTML = "👤 Skopiowano ";
            target.style.color = "#155724"; target.style.fontWeight = "bold";
            setTimeout(() => {
                target.innerHTML = originalText;
                target.style.color = "#333"; target.style.fontWeight = "400";
            }, 1200);
        } catch (err) { ui.showMessage("Błąd kopiowania loginu: " + err.message, "red"); }
    }

    // Kopiowanie Hasła
    if (target.classList.contains('password-text') && !target.classList.contains('masked')) {
        const textToCopy = target.getAttribute('data-password');
        const originalText = target.innerText;
        try {
            await navigator.clipboard.writeText(textToCopy);
            target.innerText = "Skopiowano";
            target.style.backgroundColor = "#d4edda"; target.style.color = "#155724";
            setTimeout(() => {
                target.innerText = originalText;
                target.style.backgroundColor = "#eee"; target.style.color = "#333";
            }, 1200);
        } catch (err) { ui.showMessage("Błąd kopiowania hasła: " + err.message, "red"); }
    }
});

// Uruchomienie usług autofill
listenForAutofillRequests(() => sessionEncryptionKey, () => vaultEntries);

// Start aplikacji
initialize();