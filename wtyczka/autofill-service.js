// autofill-service.js - Obsługa automatycznego uzupełniania
export function triggerAutofillToActiveTab(vaultEntries) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs && tabs[0] && tabs[0].url) {
            const activeTabUrl = tabs[0].url.toLowerCase();

            const foundEntryId = Object.keys(vaultEntries).find(id => {
                const savedUrlClean = vaultEntries[id].url
                    .toLowerCase()
                    .replace(/https?:\/\//, '')
                    .split('/')[0];
                return activeTabUrl.includes(savedUrlClean);
            });

            if (foundEntryId) {
                const entry = vaultEntries[foundEntryId];
                chrome.tabs.sendMessage(tabs[0].id, {
                    action: "fill",
                    login: entry.login,
                    password: entry.password
                }).catch(err => console.log("Content script jeszcze nie gotowy lub brak formularza."));
            }
        }
    });
}

export function listenForAutofillRequests(getEncryptionKey, getVaultEntries) {
    chrome.runtime.onMessage.addListener((request, sendResponse) => {
        if (request.action === "getCredentials") {
            const requestedDomain = request.domain;

            if (!getEncryptionKey()) {
                sendResponse({ success: false, message: "Menedżer haseł jest zablokowany." });
                return true;
            }

            const vaultEntries = getVaultEntries();
            const foundEntryId = Object.keys(vaultEntries).find(id => {
                const savedUrl = vaultEntries[id].url.toLowerCase();
                const currentUrl = requestedDomain.toLowerCase();
                return savedUrl.includes(currentUrl) || currentUrl.includes(savedUrl);
            });

            if (foundEntryId) {
                const entry = vaultEntries[foundEntryId];
                sendResponse({ success: true, login: entry.login, password: entry.password });
            } else {
                sendResponse({ success: false, message: "Brak zapisanych haseł dla tej domeny." });
            }
        }
        return true;
    });
}