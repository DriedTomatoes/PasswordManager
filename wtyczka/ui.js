// ui.js - Renderowanie elementów interfejsu użytkownika
export function showMessage(text, color) {
    const statusText = document.getElementById('status');
    statusText.innerText = text;
    statusText.style.color = color;
}

export function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

export function createEntryTemplate(item, credentials) {
    const li = document.createElement('li');
    li.className = 'entry';
    li.dataset.id = item.id;
    li.innerHTML = `
        <strong>${escapeHtml(item.url)}</strong><br>
        Login: <span class="vault-text login-text" data-login="${escapeHtml(credentials.login)}">${escapeHtml(credentials.login)}</span><br>
        <div style="display: flex; align-items: center; margin-top: 6px; width: 100%; box-sizing: border-box; line-height: 1;">
            <span class="vault-text" style="flex-shrink: 0; width: 70px; white-space: nowrap;">Hasło:</span>
            <div style="flex-grow: 1; min-width: 0; padding-right: 8px; display: flex; align-items: center;">
                <span id="pwd-${item.id}" class="password-text masked" data-password="${escapeHtml(credentials.password)}">••••••••</span>
            </div>
            <div style="flex-shrink: 0; width: 24px; text-align: right; display: flex; align-items: center; justify-content: center;">
                <button class="toggle-password-btn" data-target="pwd-${item.id}" style="background:none; border:none; cursor:pointer; font-size: 14px; padding: 0; line-height: 1;">👀</button>
            </div>
        </div>
        <div class="entry-actions" style="margin-top: 10px;">
            <button class="btn-edit">Edytuj</button>
            <button class="btn-delete">Usuń</button>
        </div>
    `;
    return li;
}

export function appendEditForm(li, entry) {
    const form = document.createElement('div');
    form.className = 'edit-form';
    form.innerHTML = `
        <input type="text" class="edit-url" value="${escapeHtml(entry.url)}" placeholder="Strona">
        <input type="text" class="edit-login" value="${escapeHtml(entry.login)}" placeholder="Login">
        <input type="password" class="edit-password" value="${escapeHtml(entry.password)}" placeholder="Hasło">
        <div class="row">
            <button class="btn-save">Zapisz</button>
            <button class="btn-cancel">Anuluj</button>
        </div>
    `;
    li.appendChild(form);
    return form;
}