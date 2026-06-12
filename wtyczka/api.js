// api.js - Obsługa żądań sieciowych do backendu
const API_URL = 'http://127.0.0.1:8000/api';

async function getToken() {
    const s = await chrome.storage.session.get('jwtToken');
    return s.jwtToken;
}

export async function registerUser(email, salt, authKeyHash) {
    return fetch(`${API_URL}/register/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, salt, auth_key_hash: authKeyHash })
    });
}

export async function fetchSalt(email) {
    const response = await fetch(`${API_URL}/get-salt/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
    });
    if (!response.ok) throw new Error("Nie znaleziono użytkownika.");
    return response.json();
}

export async function loginUser(email, authKeyHash) {
    const response = await fetch(`${API_URL}/login/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, auth_key_hash: authKeyHash })
    });
    if (!response.ok) throw new Error("Nieprawidłowe hasło.");
    return response.json();
}

export async function sendEncryptedPassword(url, encrypted) {
    const token = await getToken();
    if (!token) throw new Error("Brak tokenu JWT. Zaloguj się.");

    return fetch(`${API_URL}/passwords/`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
            url,
            iv: encrypted.iv,
            ciphertext: encrypted.ciphertext,
            tag: 'wbudowany_w_ciphertext'
        })
    });
}

export async function updateEncryptedPassword(id, newUrl, encrypted) {
    const token = await getToken();
    return fetch(`${API_URL}/passwords/${id}/`, {
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
}

export async function deletePasswordEntry(id) {
    const token = await getToken();
    return fetch(`${API_URL}/passwords/${id}/`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
    });
}

export async function fetchAllPasswords() {
    const token = await getToken();
    if (!token) throw new Error("Brak dostępu. Zaloguj się.");

    return fetch(`${API_URL}/passwords/`, {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${token}` }
    });
}