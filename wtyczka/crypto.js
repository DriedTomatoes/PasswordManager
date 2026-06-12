// crypto.js - matematyka i szyfrowanie

// Funkcja generująca losową Sól
function generateSalt() {
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    return btoa(String.fromCharCode.apply(null, salt));
}

// Funkcja wyliczająca Hash (PBKDF2) na podstawie hasła i soli
async function deriveAuthKeyHash(password, saltBase64) {
    const enc = new TextEncoder();
    
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );
    
    const saltBytes = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
    
    const derivedBits = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: saltBytes,
            iterations: 100000, 
            hash: "SHA-256"
        },
        keyMaterial,
        256 
    );
    
    return btoa(String.fromCharCode.apply(null, new Uint8Array(derivedBits)));
}

// Wyliczanie klucza szyfrującego (musi być obiektem CryptoKey dla algorytmu AES-GCM)
// extractable=true bo musimy go zrzucic do chrome.storage.session (przezywa zamkniecie popupa)
async function deriveEncryptionKey(password, saltBase64) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
    );
    const saltBytes = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));

    return await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2", salt: saltBytes, iterations: 100000, hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// Eksport klucza AES-GCM do Base64 (do chrome.storage.session)
async function exportKeyToBase64(cryptoKey) {
    const raw = await window.crypto.subtle.exportKey("raw", cryptoKey);
    return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

// Import klucza AES-GCM z Base64 z powrotem do obiektu CryptoKey
// extractable=false zeby po restore juz sie nie dalo wyciagnac
async function importKeyFromBase64(keyBase64) {
    const bytes = Uint8Array.from(atob(keyBase64), c => c.charCodeAt(0));
    return await window.crypto.subtle.importKey(
        "raw", bytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
    );
}

// Funkcja szyfrująca dane dla konkretnego URL
async function encryptData(cryptoKey, url, dataString) {
    const enc = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // Wektor inicjujący
    
    const ciphertextBuffer = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv, additionalData: enc.encode(url) },
        cryptoKey,
        enc.encode(dataString) // np. JSON z loginem i hasłem
    );

    // Pakowanie do formatu Base64, żeby łatwo wysłać na serwer
    return {
        iv: btoa(String.fromCharCode(...iv)),
        ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertextBuffer)))
    };
}

// Funkcja deszyfrująca dane pobrane z serwera
async function decryptData(cryptoKey, url, ivBase64, ciphertextBase64) {
    const enc = new TextEncoder();
    const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(ciphertextBase64), c => c.charCodeAt(0));

    const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv, additionalData: enc.encode(url) },
        cryptoKey,
        ciphertext
    );
    
    return new TextDecoder().decode(decryptedBuffer);
}