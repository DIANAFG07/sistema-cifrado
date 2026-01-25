document.addEventListener('DOMContentLoaded', async () => {

    const tabs = document.querySelectorAll('.tab-button');
    const panels = document.querySelectorAll('.tab-panel');

    tabs.forEach(btn => {
        btn.addEventListener('click', () => {
            tabs.forEach(b => b.classList.remove('active'));
            panels.forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(btn.dataset.tab).classList.add('active');
        });
    });

    /** GENERAR CLAVES */
    document.getElementById('generateBtn').addEventListener('click', async () => {
        try {
            const pass = password.value;
            const confirm = passwordConfirm.value;

            if (!strongPassword(pass))
                throw new Error('Contraseña débil o no cumple requisitos de seguridad');

            if (pass !== confirm)
                throw new Error('Las contraseñas no coinciden');

            await rsaCrypto.generateKeyPair();
            await rsaCrypto.generateSigningKeyPair();

            const pub = await rsaCrypto.exportPublicKey();
            const priv = await rsaCrypto.exportPrivateKey(pass);

            const signPub = await rsaCrypto.exportSignPublicKey();
            const signPriv = await rsaCrypto.exportSignPrivateKey(pass);

            await storageManager.saveKey('publicKey', pub);
            await storageManager.saveKey('privateKey', priv);
            await storageManager.saveKey('signPublicKey', signPub);
            await storageManager.saveKey('signPrivateKey', signPriv);

            keyStatus.textContent = 'Claves RSA y firma listas';
            toast('Claves generadas correctamente', 'success');

        } catch (err) {
            console.error(err);
            toast(err.message || 'Error al generar claves', 'error');
        }
    });

    /** CIFRAR MENSAJE */
    encryptBtn.addEventListener('click', async () => {
        try {
            const msg = messageToEncrypt.value.trim();
            if (!msg) throw new Error('El mensaje está vacío');

            const pub = await storageManager.getKey('publicKey');
            if (!pub) throw new Error('No hay clave pública');

            await rsaCrypto.importSignPrivateKey(await storageManager.getKey('signPrivateKey'), password.value || ''); 
            rsaCrypto.publicKey = await crypto.subtle.importKey(
                "spki",
                rsaCrypto.pemToArrayBuffer(pub, 'PUBLIC KEY'),
                { name: "RSA-OAEP", hash: "SHA-256" },
                false,
                ["encrypt"]
            );

            const hash = await rsaCrypto.hashData(msg);
            const signature = await rsaCrypto.signData(hash);
            const encrypted = await rsaCrypto.encryptHybrid(msg);

            encryptResult.innerHTML = `<pre>${JSON.stringify({ payload: encrypted, hash, signature }, null, 2)}</pre>`;
            toast('Mensaje cifrado', 'success');

        } catch (err) {
            console.error(err);
            toast(err.message || 'Error al cifrar', 'error');
        }
    });

    /** DESCIFRAR MENSAJE */
    decryptBtn.addEventListener('click', async () => {
        try {
            const cipher = messageToDecrypt.value.trim();
            const pass = decryptPassword.value;

            if (!cipher || !pass) throw new Error('Faltan datos para descifrar');

            const privPem = await storageManager.getKey('privateKey');
            const signPubPem = await storageManager.getKey('signPublicKey');

            if (!privPem || !signPubPem) throw new Error('Claves faltantes');

            await rsaCrypto.importPrivateKey(privPem, pass);
            await rsaCrypto.importSignPublicKey(signPubPem);

            const obj = JSON.parse(cipher);
            const message = await rsaCrypto.decryptHybrid(obj.payload);
            const newHash = await rsaCrypto.hashData(message);

            const valid = await rsaCrypto.verifySignature(newHash, obj.signature, rsaCrypto.signKeyPair.publicKey);
            if (!valid) throw new Error('Firma inválida');

            decryptResult.innerHTML = `<pre>${message}</pre>`;
            toast('Mensaje verificado y descifrado', 'success');

        } catch (err) {
            try { checkAttempts(); } catch(e){ toast(e.message,'error'); return; }
            console.error(err);
            toast('Contraseña incorrecta o mensaje inválido', 'error');
        }
    });

    /** BOTONES DE EXPORT/IMPORT/DELETE */
    document.getElementById('exportPublicBtn').addEventListener('click', async () => {
        try {
            const pub = await storageManager.getKey('publicKey');
            if (!pub) return toast('No hay clave pública para exportar', 'error');
            downloadFile(pub, 'rsa_public.pem');
            toast('Clave pública exportada', 'success');
        } catch (err) { console.error(err); toast('Error al exportar clave pública','error'); }
    });

    document.getElementById('exportPrivateBtn').addEventListener('click', async () => {
        try {
            const priv = await storageManager.getKey('privateKey');
            if (!priv) return toast('No hay clave privada para exportar', 'error');
            downloadFile(priv, 'rsa_private_encrypted.pem');
            toast('Clave privada exportada', 'success');
        } catch (err) { console.error(err); toast('Error al exportar clave privada','error'); }
    });

    document.getElementById('importPublicBtn').addEventListener('click', async () => {
        try {
            const file = importPublicFile.files[0];
            if (!file) throw new Error('Selecciona un archivo');
            const text = await file.text();
            if (!text.includes('BEGIN PUBLIC KEY')) throw new Error('Archivo no válido');
            await crypto.subtle.importKey("spki", rsaCrypto.pemToArrayBuffer(text,'PUBLIC KEY'), {name:"RSA-OAEP",hash:"SHA-256"}, false, ["encrypt"]);
            await storageManager.saveKey('publicKey', text);
            toast('Clave pública importada', 'success');
        } catch (err) { console.error(err); toast('Clave pública inválida','error'); }
    });

    document.getElementById('importPrivateBtn').addEventListener('click', async () => {
        try {
            const file = importPrivateFile.files[0];
            if (!file) throw new Error('Selecciona un archivo');
            const text = await file.text();
            if (!text.includes('ENCRYPTED PRIVATE KEY')) throw new Error('Archivo no válido');
            await storageManager.saveKey('privateKey', text);
            toast('Clave privada importada', 'success');
        } catch (err) { console.error(err); toast('Clave privada inválida','error'); }
    });

    document.getElementById('deleteKeysBtn').addEventListener('click', async () => {
        try {
            if (!confirm('⚠️ Esta acción eliminará TODAS las claves.\n¿Deseas continuar?')) return;
            await storageManager.deleteAllKeys();
            keyStatus.textContent = 'Sin claves generadas';
            encryptResult.style.display = 'none';
            decryptResult.style.display = 'none';
            toast('Claves eliminadas correctamente', 'success');
        } catch (err) { console.error(err); toast('Error al eliminar claves','error'); }
    });

});

/** TOAST SIMPLE */
function toast(msg, type){
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.className = `toast show ${type}`;
    setTimeout(()=> t.classList.remove('show'),3000);
}

/** DESCARGAR ARCHIVO */
function downloadFile(content, filename){
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href=url; a.download=filename; a.click();
    URL.revokeObjectURL(url);
}

/** VALIDACIÓN FUERTE CONTRASEÑA */
function strongPassword(p){
    return (
        p.length>=12 &&
        /[A-Z]/.test(p) &&
        /[a-z]/.test(p) &&
        /[0-9]/.test(p) &&
        /[^A-Za-z0-9]/.test(p)
    );
}

/** CONTROL DE INTENTOS */
let attempts=0; const MAX_ATTEMPTS=5;
function checkAttempts(){
    attempts++;
    if(attempts>=MAX_ATTEMPTS) throw new Error('Demasiados intentos. Recarga la página.');
}
