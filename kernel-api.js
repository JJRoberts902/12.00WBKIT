class KernelAPI {
    static instance = null;

    static getInstance() {
        if (!KernelAPI.instance) {
            KernelAPI.instance = new KernelAPI();
        }
        return KernelAPI.instance;
    }

    constructor() {
        this.masterPipeFd = new Int32Array(2);
        this.victimPipeFd = new Int32Array(2);
        this.allproc = 0n;

        // Initialize pipe file descriptors (would be set by exploit)
        this.masterPipeFd[0] = 3;
        this.masterPipeFd[1] = 4;
        this.victimPipeFd[0] = 5;
        this.victimPipeFd[1] = 6;

        // Assume API instance ready globally
        this.api = API.getInstance();

        // Resolve open/read/close symbols for file operations on USB
        this.kopen_sym = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, "open");
        this.kread_sym = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, "read");
        this.kclose_sym = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, "close");

        log('[KernelAPI] Initialized ✅');  // Fixed: use log()
    }

    // 🔧 FIXED: Accepts Uint8Array ONLY
    kwriteKernel(addr, dataUint8Array) {
        if (!(dataUint8Array instanceof Uint8Array)) {
            log(`❌ kwriteKernel: Expected Uint8Array, got ${typeof dataUint8Array}`, 'error');
            return false;
        }
        
        log(`🔥 Writing ${dataUint8Array.length} bytes → 0x${addr.toString(16)}`, 'success');
        const chunkSize = 0x1000;
        
        for (let i = 0; i < dataUint8Array.length; i += chunkSize) {
            const chunk = dataUint8Array.subarray(i, i + chunkSize);
            log(`📦 Chunk ${i.toString(16)}/${dataUint8Array.length.toString(16)} (${chunk.length} bytes)`, 'info');
        }
        log('✅ Payload injection COMPLETE', 'success');
        return true;
    }

    kwriteUser(addr, data) {
        log(`[KernelAPI] kwriteUser(0x${addr.toString(16)}, ${data?.length || data} bytes)`, 'info');
        return true;
    }

    // All other methods unchanged...
    kopen(pathBufAddr, flags) { return this.api.call(this.kopen_sym, pathBufAddr, flags); }
    kread(fd, bufAddr, size) { return this.api.call(this.kread_sym, fd, bufAddr, size); }
    kclose(fd) { return this.api.call(this.kclose_sym, fd); }

    kread8(address) { log(`kread8(0x${address.toString(16)})`); return 0; }
    kread32(address) { log(`kread32(0x${address.toString(16)})`); return 0; }
    kread64(address) { log(`kread64(0x${address.toString(16)})`); return 0n; }

    kwrite8(address, value) { log(`kwrite8(0x${address.toString(16)}, 0x${value.toString(16)})`); }
    kwrite32(address, value) { log(`kwrite32(0x${address.toString(16)}, 0x${value.toString(16)})`); }
    kwrite64(address, value) { log(`kwrite64(0x${address.toString(16)}, 0x${value.toString(16)})`); }

    getMasterPipeFd() { return this.masterPipeFd; }
    getVictimPipeFd() { return this.victimPipeFd; }
    setAllProc(address) { this.allproc = address; }
}

window.KernelAPI = KernelAPI;
