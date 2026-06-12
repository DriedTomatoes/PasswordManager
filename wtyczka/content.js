// content.js - Wstrzykiwanie danych na strone

chrome.runtime.onMessage.addListener((request) => {
    if (request.action === "fill") {
        autofillFields(request.login, request.password);
    }
});

// Obsluga na wypadek, gdyby popup byl juz otwarty
(function() {
    const currentDomain = window.location.hostname;
    chrome.runtime.sendMessage({ action: "getCredentials", domain: currentDomain }, (response) => {
        if (response && response.success) {
            autofillFields(response.login, response.password);
        }
    });
})();

// Funkcja do wypełniania pól logowania i hasła
function autofillFields(login, password) {
    const passwordField = document.querySelector('input[type="password"]');
    if (!passwordField) return;

    const loginField = document.querySelector('input[type="email"]') || 
                       document.querySelector('input[name="login"]') || 
                       document.querySelector('input[name="username"]') ||
                       document.querySelector('input[type="text"]');

    if (loginField) {
        loginField.focus();
        loginField.value = login;
        loginField.dispatchEvent(new Event('input', { bubbles: true }));
        loginField.dispatchEvent(new Event('change', { bubbles: true }));
        loginField.blur();
    }

    passwordField.focus();
    passwordField.value = password;
    passwordField.dispatchEvent(new Event('input', { bubbles: true }));
    passwordField.dispatchEvent(new Event('change', { bubbles: true }));
    passwordField.blur();
}