/**
 * Módulo de Cifrado RSA + Firma Digital
 * Utiliza Web Crypto API para operaciones criptográficas
 */

class RSACrypto {
    constructor() {
        this.publicKey = null;
        this.privateKey = null;
        this.keyPair = null;
        this.signKeyPair = null;
    }

    /** GENERACIÓN DE CLAVES RSA */
    async generateKeyPair() {
        try {
            this.keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "RSA-OAEP",
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: "SHA-256"
                },
                true,
                ["encrypt", "decrypt"]
            );
            this.publicKey = this.keyPair.publicKey;
            this.privateKey = this.keyPair.privateKey;
            return this.keyPair;
        } catch (error) {
            throw new Error(`Error al generar claves: ${error.message}`);
        }
    }

    /** EXPORTAR CLAVES PÚBLICA Y PRIVADA */
    async exportPublicKey() {
        const exported = await crypto.subtle.exportKey("spki", this.publicKey);
        return this.arrayBufferToPem(exported, 'PUBLIC KEY');
    }

    async exportPrivateKey(password) {
        const exported = await crypto.subtle.exportKey("pkcs8", this.privateKey);
        return await this.encryptPrivateKey(exported, password);
    }

    /** CIFRADO DE CLAVE PRIVADA CON CONTRASEÑA */
    async encryptPrivateKey(keyData, password) {
        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            "raw", enc.encode(password), "PBKDF2", false, ["deriveBits", "deriveKey"]
        );

        const salt = crypto.getRandomValues(new Uint8Array(16));
        const key = await crypto.subtle.deriveKey(
            { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt"]
        );

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, keyData);

        const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
        result.set(salt, 0);
        result.set(iv, salt.length);
        result.set(new Uint8Array(encrypted), salt.length + iv.length);

        return this.arrayBufferToPem(result.buffer, 'ENCRYPTED PRIVATE KEY');
    }

    /** DESCIFRADO DE CLAVE PRIVADA */
    async decryptPrivateKey(encryptedPem, password) {
        const data = new Uint8Array(this.pemToArrayBuffer(encryptedPem, 'ENCRYPTED PRIVATE KEY'));
        const salt = data.slice(0, 16);
        const iv = data.slice(16, 28);
        const encrypted = data.slice(28);

        const enc = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            "raw", enc.encode(password), "PBKDF2", false, ["deriveKey", "deriveBits"]
        );

        const key = await crypto.subtle.deriveKey(
            { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["decrypt"]
        );

        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);
        return decrypted;
    }

    /** CIFRADO Y DESCIFRADO SIMPLE */
    async encryptMessage(message) {
        const enc = new TextEncoder();
        const encrypted = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, this.publicKey, enc.encode(message));
        return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
    }

    async decryptMessage(cipherText) {
        const encrypted = Uint8Array.from(atob(cipherText), c => c.charCodeAt(0));
        const decrypted = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, this.privateKey, encrypted);
        return new TextDecoder().decode(decrypted);
    }

    /** UTILIDADES PEM */
    arrayBufferToPem(buffer, label) {
        const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
        const formatted = base64.match(/.{1,64}/g).join('\n');
        return `-----BEGIN ${label}-----\n${formatted}\n-----END ${label}-----`;
    }

    pemToArrayBuffer(pem, label) {
        const b64 = pem.replace(`-----BEGIN ${label}-----`, '')
                       .replace(`-----END ${label}-----`, '')
                       .replace(/\s/g, '');
        return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
    }

    /** CIFRADO HÍBRIDO RSA + AES */
    async generateAESKey() {
        return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    }

    async encryptHybrid(message) {
        const aesKey = await this.generateAESKey();
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encryptedData = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, new TextEncoder().encode(message));
        const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
        const encryptedKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, this.publicKey, rawAesKey);

        return btoa(JSON.stringify({
            key: Array.from(new Uint8Array(encryptedKey)),
            iv: Array.from(iv),
            data: Array.from(new Uint8Array(encryptedData))
        }));
    }

    async decryptHybrid(payload) {
        const obj = JSON.parse(atob(payload));
        const aesKeyRaw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, this.privateKey, new Uint8Array(obj.key));
        const aesKey = await crypto.subtle.importKey("raw", aesKeyRaw, { name: "AES-GCM" }, false, ["decrypt"]);
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(obj.iv) }, aesKey, new Uint8Array(obj.data));
        return new TextDecoder().decode(decrypted);
    }

    /** FIRMAS DIGITALES */
    async generateSigningKeyPair() {
        this.signKeyPair = await crypto.subtle.generateKey(
            { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            true,
            ["sign", "verify"]
        );
    }

    async signData(data) {
        const signature = await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, this.signKeyPair.privateKey, new TextEncoder().encode(data));
        return btoa(String.fromCharCode(...new Uint8Array(signature)));
    }

    async verifySignature(data, signature, publicKey) {
        return crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, publicKey, Uint8Array.from(atob(signature), c => c.charCodeAt(0)), new TextEncoder().encode(data));
    }

    async exportSignPublicKey() {
        const key = await crypto.subtle.exportKey("spki", this.signKeyPair.publicKey);
        return this.arrayBufferToPem(key, 'PUBLIC KEY');
    }

    async exportSignPrivateKey(password) {
        const key = await crypto.subtle.exportKey("pkcs8", this.signKeyPair.privateKey);
        return await this.encryptPrivateKey(key, password);
    }

    async importSignPublicKey(pem) {
        this.signKeyPair = this.signKeyPair || {};
        this.signKeyPair.publicKey = await crypto.subtle.importKey(
            "spki",
            this.pemToArrayBuffer(pem, 'PUBLIC KEY'),
            { name: "RSA-PSS", hash: "SHA-256" },
            false,
            ["verify"]
        );
    }

    async importSignPrivateKey(pem, password) {
        const raw = await this.decryptPrivateKey(pem, password);
        this.signKeyPair = this.signKeyPair || {};
        this.signKeyPair.privateKey = await crypto.subtle.importKey(
            "pkcs8",
            raw,
            { name: "RSA-PSS", hash: "SHA-256" },
            false,
            ["sign"]
        );
    }

    /** HASH */
    async hashData(data) {
        const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
        return btoa(String.fromCharCode(...new Uint8Array(hash)));
    }
}

const rsaCrypto = new RSACrypto();
