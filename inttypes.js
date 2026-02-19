class Int8 { static SIZE = 1; }
class Int32 { 
    static SIZE = 4;
    constructor() { this.value = 0; }
    set(v) { this.value = v; }
    address() { return 0; }
}
class Int64 { static SIZE = 8; }

class Int32Array extends Array {
    constructor(length) {
        super(length);
        this._address = Int32Array._nextAddress++;
    }
    static _nextAddress = 0x200000;
    
    // 🔧 FIXED: Return BigInt for kernel compat
    address() { 
        return BigInt(this._address); 
    }
}

window.Int8 = Int8;
window.Int32 = Int32;
window.Int64 = Int64;
window.Int32Array = Int32Array;
