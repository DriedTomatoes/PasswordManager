// crypto.js - Plik odpowiedzialny za matematykę i szyfrowanie

// Funkcja generująca losową Sól (Salt)
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
        false, 
        ["encrypt", "decrypt"]
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