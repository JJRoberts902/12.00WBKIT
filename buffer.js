// buffer.js - Minimal Buffer class for PS5/PS4 exploit sim

class Buffer {
    constructor(size) {
        this.size = size;
        this.data = new Uint8Array(size);
        this._address = Buffer._nextAddress++;
    }

    static _nextAddress = 0x100000; // Simulate memory address

    address() {
        // Return a fake but unique address for simulation
        return this._address;
    }

    fill(value) {
        this.data.fill(value);
    }

    putByte(offset, value) {
        this.data[offset] = value & 0xFF;
    }

    putInt(offset, value) {
        // Write as 4 bytes, little-endian
        for (let i = 0; i < 4; i++) {
            this.data[offset + i] = (value >> (i * 8)) & 0xFF;
        }
    }

    putLong(offset, value) {
        // Write as 8 bytes, little-endian. Accepts a number or BigInt.
        let v = BigInt(value);
        for (let i = 0; i < 8; i++) {
            this.data[offset + i] = Number((v >> BigInt(i * 8)) & 0xFFn);
        }
    }

    getInt(offset) {
        // Read 4 bytes as little-endian unsigned int
        let val = 0;
        for (let i = 0; i < 4; i++) {
            val |= this.data[offset + i] << (i * 8);
        }
        return val >>> 0;
    }

    getLong(offset) {
        // Read 8 bytes as little-endian BigInt
        let val = 0n;
        for (let i = 0; i < 8; i++) {
            val |= BigInt(this.data[offset + i]) << BigInt(i * 8);
        }
        return val;
    }
}

// Export to global scope
window.Buffer = Buffer;
