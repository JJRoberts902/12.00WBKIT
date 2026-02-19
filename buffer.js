class Buffer {
    constructor(size) {
        this.size = size;
        this.data = new Uint8Array(size);
        this._address = Buffer._nextAddress++;
    }

    static _nextAddress = 0x100000;

    address() { return this._address; }
    fill(value) { this.data.fill(value); }

    putByte(offset, value) {
        this.data[offset] = value & 0xFF;
    }

    putInt(offset, value) {
        for (let i = 0; i < 4; i++) {
            this.data[offset + i] = (value >> (i * 8)) & 0xFF;
        }
    }

    // 🔧 FIXED: BigInt coercion + Number() safety
    putLong(offset, value) {
        let v = BigInt(value);
        for (let i = 0; i < 8; i++) {
            this.data[offset + i] = Number((v >> BigInt(i * 8)) & 0xFFn);
        }
    }

    getInt(offset) {
        let val = 0;
        for (let i = 0; i < 4; i++) {
            val |= this.data[offset + i] << (i * 8);
        }
        return val >>> 0;
    }

    getLong(offset) {
        let val = 0n;
        for (let i = 0; i < 8; i++) {
            val |= BigInt(this.data[offset + i]) << BigInt(i * 8);
        }
        return val;
    }
}

window.Buffer = Buffer;
