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

    console.log('[KernelAPI] Initialized');
  }

  kopen(pathBufAddr, flags) {
    return this.api.call(this.kopen_sym, pathBufAddr, flags);
  }

  kread(fd, bufAddr, size) {
    return this.api.call(this.kread_sym, fd, bufAddr, size);
  }

  kclose(fd) {
    return this.api.call(this.kclose_sym, fd);
  }

  // Kernel read primitives logging
  kread8(address) {
    console.log(`[KernelAPI] kread8(0x${address.toString(16)})`);
    return 0;
  }

  kread32(address) {
    console.log(`[KernelAPI] kread32(0x${address.toString(16)})`);
    return 0;
  }

  kread64(address) {
    console.log(`[KernelAPI] kread64(0x${address.toString(16)})`);
    return 0n;
  }
// Add after constructor:
kwriteUser(addr, data) {
    console.log(`[KernelAPI] kwriteUser(0x${addr.toString(16)}, ${data.length} bytes)`);
    return true;  // Sim success
}

// Fix kwriteKernel logging:
kwriteKernel(addr, dataUint8Array) {
    log(`🔥 Writing ${dataUint8Array.length} bytes to 0x${addr.toString(16)}`, 'success');
    // Your existing chunk logic...
}
  // Kernel write primitives logging
  kwrite8(address, value) {
    console.log(`[KernelAPI] kwrite8(0x${address.toString(16)}, 0x${value.toString(16)})`);
  }

  kwrite32(address, value) {
    console.log(`[KernelAPI] kwrite32(0x${address.toString(16)}, 0x${value.toString(16)})`);
  }

  kwrite64(address, value) {
    console.log(`[KernelAPI] kwrite64(0x${address.toString(16)}, 0x${value.toString(16)})`);
  }

  // Chunked kernel memory write for injecting payloads like GoldHEN.bin
  kwriteKernel(addr, dataUint8Array) {
    const chunkSize = 0x1000; // 4KB chunks
    for (let i = 0; i < dataUint8Array.length; i += chunkSize) {
      const chunk = dataUint8Array.subarray(i, i + chunkSize);
      console.log(`[KernelAPI] Writing ${chunk.length} bytes to kernel at 0x${(addr + i).toString(16)}`);
      // Implement actual kernel memory write syscall or primitive here
      // Example: this.api.call(this.writeKernelSym, addr + i, chunk.address(), chunk.length);
      // For now just simulated logging
    }
  }

  // Getters/Setters for pipe FDs and allproc pointer
  getMasterPipeFd() {
    return this.masterPipeFd;
  }

  getVictimPipeFd() {
    return this.victimPipeFd;
  }

  setAllProc(address) {
    this.allproc = address;
  }
}

