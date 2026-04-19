document.addEventListener('DOMContentLoaded', async () => {
    const wizard = {
        steps: ['generate', 'encrypt', 'decrypt', 'export'],
        labels: ['Generar/Importar claves', 'Cifrar mensaje', 'Descifrar mensaje', 'Respaldar claves (opcional)'],
        active: false,
        currentIndex: 0,
        backupTouched: false
    };

    const refs = {
        tabs: document.querySelectorAll('.tab-button'),
        panels: document.querySelectorAll('.tab-panel'),
        keyStatus: document.getElementById('keyStatus'),
        infoStatus: document.getElementById('infoStatus'),
        password: document.getElementById('password'),
        passwordConfirm: document.getElementById('passwordConfirm'),
        passwordStrengthBar: document.getElementById('passwordStrengthBar'),
        passwordStrengthText: document.getElementById('passwordStrengthText'),
        generateBtn: document.getElementById('generateBtn'),
        messageToEncrypt: document.getElementById('messageToEncrypt'),
        encryptSignPassword: document.getElementById('encryptSignPassword'),
        charCount: document.getElementById('charCount'),
        encryptBtn: document.getElementById('encryptBtn'),
        copyEncryptResultBtn: document.getElementById('copyEncryptResultBtn'),
        messageToDecrypt: document.getElementById('messageToDecrypt'),
        decryptPassword: document.getElementById('decryptPassword'),
        decryptBtn: document.getElementById('decryptBtn'),
        copyDecryptResultBtn: document.getElementById('copyDecryptResultBtn'),
        encryptResult: document.getElementById('encryptResult'),
        decryptResult: document.getElementById('decryptResult'),
        exportPublicBtn: document.getElementById('exportPublicBtn'),
        exportPrivateBtn: document.getElementById('exportPrivateBtn'),
        exportSignPublicBtn: document.getElementById('exportSignPublicBtn'),
        exportSignPrivateBtn: document.getElementById('exportSignPrivateBtn'),
        importPublicFile: document.getElementById('importPublicFile'),
        importPrivateFile: document.getElementById('importPrivateFile'),
        importSignPublicFile: document.getElementById('importSignPublicFile'),
        importSignPrivateFile: document.getElementById('importSignPrivateFile'),
        importPublicBtn: document.getElementById('importPublicBtn'),
        importPrivateBtn: document.getElementById('importPrivateBtn'),
        importSignPublicBtn: document.getElementById('importSignPublicBtn'),
        importSignPrivateBtn: document.getElementById('importSignPrivateBtn'),
        deleteKeysBtn: document.getElementById('deleteKeysBtn'),
        stepGenerate: document.getElementById('stepGenerate'),
        stepEncrypt: document.getElementById('stepEncrypt'),
        stepDecrypt: document.getElementById('stepDecrypt'),
        startWizardBtn: document.getElementById('startWizardBtn'),
        wizardPrevBtn: document.getElementById('wizardPrevBtn'),
        wizardNextBtn: document.getElementById('wizardNextBtn'),
        wizardStatus: document.getElementById('wizardStatus')
    };

    refs.tabs.forEach((btn) => {
        btn.addEventListener('click', () => {
            setActiveTab(btn.dataset.tab, refs);

            if (wizard.active) {
                const index = wizard.steps.indexOf(btn.dataset.tab);
                if (index >= 0) {
                    wizard.currentIndex = index;
                    updateWizardControls(wizard, refs);
                }
            }
        });
    });

    refs.messageToEncrypt.addEventListener('input', () => {
        const length = refs.messageToEncrypt.value.length;
        refs.charCount.textContent = `${length} / 190 caracteres`;
        autoGrowTextarea(refs.messageToEncrypt);
    });

    refs.messageToDecrypt.addEventListener('input', () => {
        autoGrowTextarea(refs.messageToDecrypt);
    });

    refs.password.addEventListener('input', () => {
        renderPasswordStrength(refs.password.value, refs);
    });

    refs.generateBtn.addEventListener('click', async () => {
        try {
            const pass = refs.password.value;
            const confirm = refs.passwordConfirm.value;

            if (!strongPassword(pass)) {
                throw new Error(getPasswordRequirements());
            }
            if (pass !== confirm) {
                throw new Error('Las contraseñas no coinciden.');
            }

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

            refs.password.value = '';
            refs.passwordConfirm.value = '';
            renderPasswordStrength('', refs);
            await updateStatus(refs);
            if (wizard.active) {
                updateWizardControls(wizard, refs);
            }
            toast('Claves de cifrado y firma generadas correctamente.', 'success');
        } catch (error) {
            console.error(error);
            toast(error.message || 'No se pudieron generar las claves.', 'error');
        }
    });

    refs.encryptBtn.addEventListener('click', async () => {
        try {
            const message = refs.messageToEncrypt.value.trim();
            if (!message) {
                throw new Error('Escribe un mensaje antes de cifrar.');
            }

            const publicPem = await storageManager.getKey('publicKey');
            if (!publicPem) {
                throw new Error('No hay clave pública. Importa o genera una clave pública primero.');
            }

            await rsaCrypto.importPublicKey(publicPem);
            const payload = await rsaCrypto.encryptHybrid(message);

            let signed = false;
            let hash = null;
            let signature = null;

            const signPrivatePem = await storageManager.getKey('signPrivateKey');
            if (signPrivatePem) {
                const signPassword = refs.encryptSignPassword.value;
                if (signPassword) {
                    await rsaCrypto.importSignPrivateKey(signPrivatePem, signPassword);
                    hash = await rsaCrypto.hashData(message);
                    signature = await rsaCrypto.signData(hash);
                    signed = true;
                }
            }

            refs.messageToDecrypt.value = payload;
            autoGrowTextarea(refs.messageToDecrypt);

            showResult(refs.encryptResult, payload, 'success', { asTextarea: true });
            if (signed) {
                toast('Mensaje cifrado y enviado al cuadro de descifrado. Firma generada opcionalmente.', 'success');
            } else {
                toast('Mensaje cifrado y enviado al cuadro de descifrado.', 'success');
            }

            if (signed && hash && signature) {
                console.info('Firma generada para este payload:', { hash, signature });
            }
            await updateGuideSteps(refs);
            if (wizard.active) {
                updateWizardControls(wizard, refs);
            }
        } catch (error) {
            console.error(error);
            showResult(refs.encryptResult, error.message, 'error');
            toast(error.message || 'No se pudo cifrar el mensaje.', 'error');
        }
    });

    refs.decryptBtn.addEventListener('click', async () => {
        try {
            const input = refs.messageToDecrypt.value.trim();
            const password = refs.decryptPassword.value;

            if (!input) {
                throw new Error('Pega el mensaje cifrado (JSON o payload Base64).');
            }
            if (!password) {
                throw new Error('Ingresa la contraseña de tu clave privada para descifrar.');
            }

            const privatePem = await storageManager.getKey('privateKey');
            if (!privatePem) {
                throw new Error('No hay clave privada almacenada. Importa o genera una primero.');
            }

            const envelope = parseCipherEnvelope(input);
            await rsaCrypto.importPrivateKey(privatePem, password);
            const message = await rsaCrypto.decryptHybrid(envelope.payload);

            let integrityText = 'No incluida';
            let signatureText = 'No incluida';

            if (envelope.hash) {
                const calculatedHash = await rsaCrypto.hashData(message);
                if (calculatedHash !== envelope.hash) {
                    throw new Error('El hash no coincide: el contenido pudo ser alterado.');
                }
                integrityText = 'Valida (hash coincide)';
            }

            if (envelope.signature) {
                const signPublicPem = await storageManager.getKey('signPublicKey');
                if (signPublicPem) {
                    await rsaCrypto.importSignPublicKey(signPublicPem);
                    const hashForValidation = envelope.hash || await rsaCrypto.hashData(message);
                    const valid = await rsaCrypto.verifySignature(
                        hashForValidation,
                        envelope.signature,
                        rsaCrypto.signKeyPair.publicKey
                    );
                    if (!valid) {
                        throw new Error('La firma digital no es válida para este mensaje.');
                    }
                    signatureText = 'Valida';
                } else {
                    signatureText = 'No verificada (falta clave publica de firma)';
                }
            }

            const output = [
                `Mensaje descifrado:\n${message}`,
                `\nIntegridad: ${integrityText}`,
                `\nFirma: ${signatureText}`
            ].join('');

            showResult(refs.decryptResult, output, 'success');
            toast('Mensaje descifrado correctamente.', 'success');
            await updateGuideSteps(refs);
            if (wizard.active) {
                updateWizardControls(wizard, refs);
            }
        } catch (error) {
            console.error(error);
            showResult(refs.decryptResult, error.message, 'error');
            toast(error.message || 'No se pudo descifrar el mensaje.', 'error');
        }
    });

    refs.exportPublicBtn.addEventListener('click', async () => {
        try {
            const publicKey = await storageManager.getKey('publicKey');
            if (!publicKey) {
                throw new Error('No hay clave publica para exportar.');
            }
            downloadFile(publicKey, 'rsa_public.pem');
            wizard.backupTouched = true;
            if (wizard.active) {
                updateWizardControls(wizard, refs);
            }
            toast('Clave publica exportada.', 'success');
        } catch (error) {
            console.error(error);
            toast(error.message || 'No se pudo exportar la clave publica.', 'error');
        }
    });

    refs.exportPrivateBtn.addEventListener('click', async () => {
        try {
            const privateKey = await storageManager.getKey('privateKey');
            if (!privateKey) {
                throw new Error('No hay clave privada para exportar.');
            }
            downloadFile(privateKey, 'rsa_private_encrypted.pem');
            wizard.backupTouched = true;
            if (wizard.active) {
                updateWizardControls(wizard, refs);
            }
            toast('Clave privada exportada.', 'success');
        } catch (error) {
            console.error(error);
            toast(error.message || 'No se pudo exportar la clave privada.', 'error');
        }
    });

    refs.exportSignPublicBtn.addEventListener('click', async () => {
        try {
            const signPublicKey = await storageManager.getKey('signPublicKey');
            if (!signPublicKey) {
                throw new Error('No hay clave publica de firma para exportar.');
            }
            downloadFile(signPublicKey, 'rsa_sign_public.pem');
            wizard.backupTouched = true;
            if (wizard.active) {
                updateWizardControls(wizard, refs);
            }
            toast('Clave publica de firma exportada.', 'success');
        } catch (error) {
            console.error(error);
            toast(error.message || 'No se pudo exportar la clave publica de firma.', 'error');
        }
    });

    refs.exportSignPrivateBtn.addEventListener('click', async () => {
        try {
            const signPrivateKey = await storageManager.getKey('signPrivateKey');
            if (!signPrivateKey) {
                throw new Error('No hay clave privada de firma para exportar.');
            }
            downloadFile(signPrivateKey, 'rsa_sign_private_encrypted.pem');
            wizard.backupTouched = true;
            if (wizard.active) {
                updateWizardControls(wizard, refs);
            }
            toast('Clave privada de firma exportada.', 'success');
        } catch (error) {
            console.error(error);
            toast(error.message || 'No se pudo exportar la clave privada de firma.', 'error');
        }
    });

    refs.importPublicBtn.addEventListener('click', async () => {
        try {
            const file = refs.importPublicFile.files[0];
            if (!file) {
                throw new Error('Selecciona el archivo de clave publica.');
            }
            const text = await file.text();
            await rsaCrypto.importPublicKey(text);
            await storageManager.saveKey('publicKey', text);
            wizard.backupTouched = true;
            await updateStatus(refs);
            if (wizard.active) {
                updateWizardControls(wizard, refs);
            }
            toast('Clave publica importada correctamente.', 'success');
        } catch (error) {
            console.error(error);
            toast(error.message || 'La clave publica no es valida.', 'error');
        }
    });

    refs.importPrivateBtn.addEventListener('click', async () => {
        try {
            const file = refs.importPrivateFile.files[0];
            if (!file) {
                throw new Error('Selecciona el archivo de clave privada.');
            }
            const text = await file.text();
            rsaCrypto.pemToArrayBuffer(text, 'ENCRYPTED PRIVATE KEY');
            await storageManager.saveKey('privateKey', text);
            wizard.backupTouched = true;
            await updateStatus(refs);
            if (wizard.active) {
                updateWizardControls(wizard, refs);
            }
            toast('Clave privada importada correctamente.', 'success');
        } catch (error) {
            console.error(error);
            toast(error.message || 'La clave privada no es valida.', 'error');
        }
    });

    refs.importSignPublicBtn.addEventListener('click', async () => {
        try {
            const file = refs.importSignPublicFile.files[0];
            if (!file) {
                throw new Error('Selecciona el archivo de firma publica.');
            }
            const text = await file.text();
            await rsaCrypto.importSignPublicKey(text);
            await storageManager.saveKey('signPublicKey', text);
            wizard.backupTouched = true;
            await updateStatus(refs);
            if (wizard.active) {
                updateWizardControls(wizard, refs);
            }
            toast('Firma publica importada correctamente.', 'success');
        } catch (error) {
            console.error(error);
            toast(error.message || 'La firma publica no es valida.', 'error');
        }
    });

    refs.importSignPrivateBtn.addEventListener('click', async () => {
        try {
            const file = refs.importSignPrivateFile.files[0];
            if (!file) {
                throw new Error('Selecciona el archivo de firma privada.');
            }
            const text = await file.text();
            rsaCrypto.pemToArrayBuffer(text, 'ENCRYPTED PRIVATE KEY');
            await storageManager.saveKey('signPrivateKey', text);
            wizard.backupTouched = true;
            await updateStatus(refs);
            if (wizard.active) {
                updateWizardControls(wizard, refs);
            }
            toast('Firma privada importada correctamente.', 'success');
        } catch (error) {
            console.error(error);
            toast(error.message || 'La firma privada no es valida.', 'error');
        }
    });

    refs.copyEncryptResultBtn.addEventListener('click', async () => {
        await copyResultFromBox(refs.encryptResult, 'resultado de cifrado');
    });

    refs.copyDecryptResultBtn.addEventListener('click', async () => {
        await copyResultFromBox(refs.decryptResult, 'resultado de descifrado');
    });

    refs.deleteKeysBtn.addEventListener('click', async () => {
        try {
            const confirmed = confirm('Esta accion eliminara todas las claves guardadas. ¿Deseas continuar?');
            if (!confirmed) {
                return;
            }

            await storageManager.deleteAllKeys();
            wizard.backupTouched = false;
            refs.importPublicFile.value = '';
            refs.importPrivateFile.value = '';
            refs.importSignPublicFile.value = '';
            refs.importSignPrivateFile.value = '';
            refs.encryptResult.style.display = 'none';
            refs.decryptResult.style.display = 'none';
            await updateStatus(refs);
            if (wizard.active) {
                wizard.currentIndex = 0;
                setActiveTab('generate', refs);
                updateWizardControls(wizard, refs);
            }
            toast('Todas las claves fueron eliminadas.', 'success');
        } catch (error) {
            console.error(error);
            toast('No se pudieron eliminar las claves.', 'error');
        }
    });

    refs.startWizardBtn.addEventListener('click', () => {
        wizard.active = true;
        wizard.currentIndex = 0;
        setActiveTab(wizard.steps[wizard.currentIndex], refs);
        updateWizardControls(wizard, refs);
        toast('Wizard iniciado. Sigue los pasos en orden.', 'info');
    });

    refs.wizardPrevBtn.addEventListener('click', () => {
        if (!wizard.active || wizard.currentIndex === 0) {
            return;
        }
        wizard.currentIndex -= 1;
        setActiveTab(wizard.steps[wizard.currentIndex], refs);
        updateWizardControls(wizard, refs);
    });

    refs.wizardNextBtn.addEventListener('click', async () => {
        if (!wizard.active) {
            return;
        }

        const check = await canAdvanceWizardStep(wizard, refs);
        if (!check.ok) {
            toast(check.message, 'error');
            return;
        }

        if (wizard.currentIndex >= wizard.steps.length - 1) {
            if (!wizard.backupTouched) {
                toast('Wizard finalizado. Recomendado: exporta tus claves para backup.', 'info');
            }
            wizard.active = false;
            updateWizardControls(wizard, refs);
            if (wizard.backupTouched) {
                toast('Wizard completado. Ya puedes operar libremente.', 'success');
            }
            return;
        }

        wizard.currentIndex += 1;
        setActiveTab(wizard.steps[wizard.currentIndex], refs);
        updateWizardControls(wizard, refs);
    });

    await updateStatus(refs);
    renderPasswordStrength('', refs);
    await updateGuideSteps(refs);
    updateWizardControls(wizard, refs);
    autoGrowTextarea(refs.messageToEncrypt);
    autoGrowTextarea(refs.messageToDecrypt);
});

function setActiveTab(tabName, refs) {
    refs.tabs.forEach((button) => button.classList.remove('active'));
    refs.panels.forEach((panel) => panel.classList.remove('active'));

    const tabButton = document.querySelector(`.tab-button[data-tab="${tabName}"]`);
    const tabPanel = document.getElementById(tabName);

    if (tabButton) {
        tabButton.classList.add('active');
    }
    if (tabPanel) {
        tabPanel.classList.add('active');
    }
}

async function canAdvanceWizardStep(wizard, refs) {
    const currentStep = wizard.steps[wizard.currentIndex];

    if (currentStep === 'generate') {
        const hasPublicKey = await storageManager.getKey('publicKey');
        const hasPrivateKey = await storageManager.getKey('privateKey');
        if (!(hasPublicKey && hasPrivateKey)) {
            return {
                ok: false,
                message: 'Paso 1 incompleto: genera o importa clave publica y clave privada de cifrado.'
            };
        }
    }

    if (currentStep === 'encrypt') {
        const encryptedReady =
            refs.encryptResult.style.display !== 'none' && refs.encryptResult.className.includes('success');
        if (!encryptedReady) {
            return {
                ok: false,
                message: 'Paso 2 incompleto: cifra un mensaje para continuar.'
            };
        }
    }

    if (currentStep === 'decrypt') {
        const decryptedReady =
            refs.decryptResult.style.display !== 'none' && refs.decryptResult.className.includes('success');
        if (!decryptedReady) {
            return {
                ok: false,
                message: 'Paso 3 incompleto: descifra correctamente un mensaje para continuar.'
            };
        }
    }

    return { ok: true };
}

function updateWizardControls(wizard, refs) {
    if (!wizard.active) {
        refs.wizardStatus.textContent = 'Wizard inactivo';
        refs.startWizardBtn.disabled = false;
        refs.wizardPrevBtn.disabled = true;
        refs.wizardNextBtn.disabled = true;
        return;
    }

    refs.startWizardBtn.disabled = true;
    refs.wizardPrevBtn.disabled = wizard.currentIndex === 0;
    refs.wizardNextBtn.disabled = false;

    const stepLabel = wizard.labels[wizard.currentIndex];
    const stepNumber = wizard.currentIndex + 1;
    refs.wizardStatus.textContent = `Wizard activo: Paso ${stepNumber}/${wizard.steps.length} - ${stepLabel}`;

    if (wizard.currentIndex === wizard.steps.length - 1) {
        refs.wizardNextBtn.innerHTML = '<i class="fas fa-check"></i> Finalizar';
    } else {
        refs.wizardNextBtn.innerHTML = '<i class="fas fa-arrow-right"></i> Siguiente';
    }
}

function parseCipherEnvelope(input) {
    if (input.startsWith('{')) {
        const parsed = JSON.parse(input);
        if (!parsed.payload) {
            throw new Error('El JSON no contiene la propiedad "payload".');
        }
        return parsed;
    }

    if (!isValidBase64(input)) {
        throw new Error('El texto no es JSON valido ni payload Base64 valido.');
    }

    return { payload: input };
}

async function updateStatus(refs) {
    const publicKey = await storageManager.getKey('publicKey');
    const privateKey = await storageManager.getKey('privateKey');
    const signPublicKey = await storageManager.getKey('signPublicKey');
    const signPrivateKey = await storageManager.getKey('signPrivateKey');

    const hasEncryptionKeys = Boolean(publicKey && privateKey);
    const hasSignKeys = Boolean(signPublicKey && signPrivateKey);

    if (hasEncryptionKeys && hasSignKeys) {
        refs.keyStatus.textContent = 'Claves de cifrado y firma disponibles';
        refs.infoStatus.textContent = 'Puedes cifrar, firmar y verificar mensajes';
        return;
    }

    if (hasEncryptionKeys) {
        refs.keyStatus.textContent = 'Claves de cifrado disponibles';
        refs.infoStatus.textContent = 'Puedes cifrar y descifrar. La firma digital es opcional.';
        return;
    }

    if (publicKey || privateKey) {
        refs.keyStatus.textContent = 'Claves incompletas';
        refs.infoStatus.textContent = 'Falta importar la clave publica o privada para operar.';
        return;
    }

    refs.keyStatus.textContent = 'Sin claves generadas';
    refs.infoStatus.textContent = 'Genera o importa tus claves para comenzar';

    await updateGuideSteps(refs);
}

async function updateGuideSteps(refs) {
    const publicKey = await storageManager.getKey('publicKey');
    const privateKey = await storageManager.getKey('privateKey');
    const hasKeys = Boolean(publicKey && privateKey);
    const hasEncryptedOutput = refs.encryptResult.style.display !== 'none' && refs.encryptResult.className.includes('success');
    const hasDecryptedOutput = refs.decryptResult.style.display !== 'none' && refs.decryptResult.className.includes('success');

    refs.stepGenerate.classList.toggle('done', hasKeys);
    refs.stepEncrypt.classList.toggle('done', hasEncryptedOutput);
    refs.stepDecrypt.classList.toggle('done', hasDecryptedOutput);
}

function renderPasswordStrength(password, refs) {
    const strength = calculatePasswordStrength(password);
    refs.passwordStrengthBar.style.width = `${strength.percent}%`;
    refs.passwordStrengthBar.style.background = strength.color;
    refs.passwordStrengthText.textContent = `Fortaleza: ${strength.label}`;
}

function calculatePasswordStrength(password) {
    if (!password) {
        return { percent: 0, label: 'sin evaluar', color: '#94a3b8' };
    }

    let score = 0;
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;

    if (score <= 2) {
        return { percent: 28, label: 'debil', color: '#ef4444' };
    }
    if (score <= 4) {
        return { percent: 62, label: 'media', color: '#f59e0b' };
    }
    return { percent: 100, label: 'fuerte', color: '#10b981' };
}

async function copyResultFromBox(resultBox, label) {
    try {
        if (resultBox.style.display === 'none') {
            throw new Error(`Primero genera un ${label} para copiar.`);
        }
        const textarea = resultBox.querySelector('textarea');
        const text = (textarea ? textarea.value : resultBox.innerText).trim();
        if (!text) {
            throw new Error(`El ${label} esta vacio.`);
        }
        await navigator.clipboard.writeText(text);
        toast(`Se copio el ${label} al portapapeles.`, 'success');
    } catch (error) {
        console.error(error);
        toast(error.message || `No se pudo copiar el ${label}.`, 'error');
    }
}

function showResult(element, content, type, options = {}) {
    element.className = `result-box ${type}`;
    element.style.display = 'block';

    if (options.asTextarea) {
        element.innerHTML = '<textarea class="result-text" readonly></textarea>';
        const output = element.querySelector('textarea');
        output.value = content;
        autoGrowTextarea(output);
        return;
    }

    element.innerHTML = `<pre>${escapeHtml(content)}</pre>`;
}

function escapeHtml(text) {
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function isValidBase64(value) {
    try {
        const normalized = value.replace(/\s/g, '');
        return normalized.length > 0 && btoa(atob(normalized)) === normalized;
    } catch {
        return false;
    }
}

function toast(message, type) {
    const toastElement = document.getElementById('toast');
    toastElement.textContent = message;
    toastElement.className = `toast show ${type}`;
    setTimeout(() => toastElement.classList.remove('show'), 3200);
}

function downloadFile(content, filename) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
}

function strongPassword(password) {
    return (
        password.length >= 12 &&
        /[A-Z]/.test(password) &&
        /[a-z]/.test(password) &&
        /[0-9]/.test(password) &&
        /[^A-Za-z0-9]/.test(password)
    );
}

function getPasswordRequirements() {
    return 'La contraseña debe tener minimo 12 caracteres, una mayuscula, una minuscula, un numero y un simbolo.';
}

function autoGrowTextarea(textarea) {
    if (!textarea) {
        return;
    }

    textarea.style.height = 'auto';
    textarea.style.height = `${Math.max(textarea.scrollHeight, 96)}px`;
}
