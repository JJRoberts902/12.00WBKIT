// api.js - API class for PS4/PS5 exploit framework

class API {
    static instance = null;
    static LIBKERNEL_MODULE_HANDLE = 1;

    static getInstance() {
        if (!API.instance) {
            API.instance = new API();
        }
        return API.instance;
    }

    constructor() {
        this.symbolTable = new Map();
        [
            "dup","close","read","readv","write","writev",
            "ioctl","pipe","kqueue","socket","socketpair","recvmsg","sendmsg",
            "getsockopt","setsockopt","setuid","getpid","sched_yield",
            "cpuset_setaffinity","rtprio_thread","__sys_netcontrol"
        ].forEach((sym, idx) => this.symbolTable.set(sym, idx+100));
    }

    dlsym(handle, symbol) {
        if (this.symbolTable.has(symbol)) {
            return this.symbolTable.get(symbol);
        }
        console.log(`[API] dlsym: Symbol not found: ${symbol}, returning 0`);
        return 0;
    }

    call(symbolHandle, ...args) {
        console.log(`[API] call: handle=${symbolHandle}, args=${JSON.stringify(args)}`);
        return 0;
    }
}

// Make API global
window.API = API;
