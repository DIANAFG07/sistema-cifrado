/**
 * Módulo de Almacenamiento
 * Gestiona el almacenamiento seguro de claves en IndexedDB
 */

class StorageManager {
    constructor() {
        this.dbName = 'RSACryptoSystem';
        this.version = 1;
        this.db = null;
    }

    /**
     * Inicializa la base de datos
     */
    async init() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, this.version);

            request.onerror = () => reject(request.error);
            request.onsuccess = () => {
                this.db = request.result;
                resolve();
            };

            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                
                if (!db.objectStoreNames.contains('keys')) {
                    db.createObjectStore('keys', { keyPath: 'id' });
                }
            };
        });
    }

    /**
     * Guarda una clave en la base de datos
     */
    async saveKey(id, keyData) {
        await this.init();
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(['keys'], 'readwrite');
            const store = transaction.objectStore('keys');
            const request = store.put({ id, data: keyData, timestamp: Date.now() });

            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }

    /**
     * Obtiene una clave de la base de datos
     */
    async getKey(id) {
        await this.init();
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(['keys'], 'readonly');
            const store = transaction.objectStore('keys');
            const request = store.get(id);

            request.onsuccess = () => {
                resolve(request.result ? request.result.data : null);
            };
            request.onerror = () => reject(request.error);
        });
    }

    /**
     * Elimina una clave específica
     */
    async deleteKey(id) {
        await this.init();
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(['keys'], 'readwrite');
            const store = transaction.objectStore('keys');
            const request = store.delete(id);

            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }

    /**
     * Elimina todas las claves
     */
    async deleteAllKeys() {
        await this.init();
        return new Promise((resolve, reject) => {
            const transaction = this.db.transaction(['keys'], 'readwrite');
            const store = transaction.objectStore('keys');
            const request = store.clear();

            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }

    /**
     * Verifica si existen claves
     */
    async hasKeys() {
        const publicKey = await this.getKey('publicKey');
        const privateKey = await this.getKey('privateKey');
        return !!(publicKey && privateKey);
    }
}

// Exportar instancia global
const storageManager = new StorageManager();
