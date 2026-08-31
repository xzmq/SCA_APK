"""
dynamic_unpacker.py - F-E-full: Dynamic DEX dumping via Frida.

Requires: ADB + Android emulator/device + Frida server.

Strategy:
  1. Check dynamic unpacking infrastructure availability
  2. Start headless Android emulator (if needed)
  3. Deploy Frida server to device
  4. Install and launch target APK
  5. Inject Frida DEX dump script (FRIDA-DEXDump pattern)
  6. Collect dumped DEX files from device via ADB
  7. Return paths to dumped DEX files

The Frida script hooks ART internals to enumerate and dump all loaded DEX
from memory at runtime, bypassing static encryption.
"""
import os
import sys
import time
import json
import lzma
import shutil
import subprocess
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import (
    ADB_BIN, FRIDA_BIN, FRIDA_SERVER_DEVICE_PATH, FRIDA_SERVER_PORT,
    DYNAMIC_UNPACKING_TIMEOUT, EMULATOR_AVD_NAME, EMULATOR_AVD_32_NAME,
    EMULATOR_BIN, ANDROID_SDK_ROOT, GADGET_PORT, ADB_LOCK_FILE,
)
from common import save_json

_FRIDA_SERVER_CACHE_DIR = os.path.join(
    os.path.expanduser("~"), ".cache", "frida-server"
)

_ABI_MAP = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "x86_64": "x86_64",
    "x86": "x86",
}

# Track whether the emulator was started by this pipeline (not externally)
_emulator_started_by_pipeline = False

# Debug keystore for re-signing stripped APKs
_DEBUG_KEYSTORE = os.path.join(
    os.path.expanduser("~"), ".android", "debug.keystore"
)
_DEBUG_KEYSTORE_PASS = "android"
_DEBUG_KEY_ALIAS = "androiddebugkey"


def _strip_and_resign_apk(apk_path, output_dir):
    """Strip incompatible native libs from APK and re-sign for arm64 emulator.

    If the APK contains no arm64-v8a native libraries, Android will refuse
    to install it (INSTALL_FAILED_NO_MATCHING_ABIS). This function:
      1. Checks if the APK has arm64-v8a libs — if yes, returns the original path.
      2. If not, copies the APK, removes all lib/* entries and old META-INF/*,
         and re-signs with a debug key.
      3. Returns the path to the stripped+signed APK (or None on failure).
    """
    import zipfile

    # Quick check: does the APK have arm64-v8a libs?
    has_arm64 = False
    has_any_lib = False
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for name in zf.namelist():
                if name.startswith("lib/"):
                    has_any_lib = True
                    if name.startswith("lib/arm64-v8a/"):
                        has_arm64 = True
                        break
    except Exception:
        return None  # Can't read, let original install try

    if has_arm64 or not has_any_lib:
        return apk_path  # No strip needed

    # Need to strip + re-sign
    stripped_path = os.path.join(output_dir, "stripped.apk")
    shutil.copy2(apk_path, stripped_path)

    # Delete lib/* and META-INF/* from the zip
    result = subprocess.run(
        ["zip", "-d", stripped_path, "lib/*", "META-INF/*"],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0 and "Nothing to do" not in result.stdout:
        print(f"  [!] [DynamicUnpacker] zip -d failed: {result.stderr}")
        return None

    # Ensure debug keystore exists
    jarsigner = shutil.which("jarsigner")
    if not jarsigner:
        print("  [!] [DynamicUnpacker] jarsigner not found")
        return None

    if not os.path.exists(_DEBUG_KEYSTORE):
        keytool = shutil.which("keytool")
        if not keytool:
            print("  [!] [DynamicUnpacker] keytool not found")
            return None
        os.makedirs(os.path.dirname(_DEBUG_KEYSTORE), exist_ok=True)
        subprocess.run(
            [keytool, "-genkey", "-v",
             "-keystore", _DEBUG_KEYSTORE,
             "-alias", _DEBUG_KEY_ALIAS,
             "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
             "-storepass", _DEBUG_KEYSTORE_PASS,
             "-keypass", _DEBUG_KEYSTORE_PASS,
             "-dname", "CN=Android Debug,O=Android,C=US"],
            capture_output=True, timeout=30,
        )

    # Re-sign
    result = subprocess.run(
        [jarsigner, "-sigalg", "SHA256withRSA", "-digestalg", "SHA-256",
         "-keystore", _DEBUG_KEYSTORE,
         "-storepass", _DEBUG_KEYSTORE_PASS,
         "-keypass", _DEBUG_KEYSTORE_PASS,
         stripped_path, _DEBUG_KEY_ALIAS],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        print(f"  [!] [DynamicUnpacker] jarsigner failed: {result.stderr}")
        return None

    print(f"  [+] [DynamicUnpacker] Stripped native libs + re-signed (arm64 compatible)")
    return stripped_path


# ── Frida DEX dump script (anti-detection + DEX dump) ─────────────────────────

FRIDA_DEX_DUMP_SCRIPT = r"""
console.log("[Frida] DEX dump script started (anti-detect v8)");
var libc = Process.findModuleByName("libc.so");

function findFunc(name) {
    var fn = null;
    try { fn = Module.findGlobalExportByName(name); } catch(e) {}
    if (!fn && libc) { try { fn = libc.findExportByName(name); } catch(e) {} }
    return fn;
}

// === ANTI-EMULATOR: Spoof system properties ===
var prop_get = findFunc("__system_property_get");
if (prop_get) {
    Interceptor.attach(prop_get, {
        onEnter: function(args) { this.name = args[0].readCString(); this.buf = args[1]; },
        onLeave: function(retval) {
            var n = this.name; var spoof = null;
            if (n === "ro.kernel.qemu") spoof = "0";
            else if (n === "ro.product.model") spoof = "SM-G991B";
            else if (n === "ro.product.brand") spoof = "samsung";
            else if (n === "ro.product.manufacturer") spoof = "samsung";
            else if (n === "ro.product.device") spoof = "o1s";
            else if (n === "ro.product.name") spoof = "o1sxxx";
            else if (n === "ro.hardware") spoof = "exynos2100";
            else if (n === "ro.boot.hardware") spoof = "exynos2100";
            // DON'T spoof ro.board.platform — EGL needs it to find GPU libs
            // else if (n === "ro.board.platform") spoof = "exynos2100";
            else if (n === "ro.product.board") spoof = "exynos2100";
            else if (n === "ro.build.fingerprint") spoof = "samsung/o1sxxx/o1s:13/TP1A.220624.014/S991BXXU3CVF1:user/release-keys";
            else if (n === "ro.build.tags") spoof = "release-keys";
            else if (n === "ro.build.type") spoof = "user";
            else if (n === "ro.debuggable") spoof = "0";
            else if (n === "ro.secure") spoof = "1";
            else if (n === "ro.build.flavor") spoof = "o1sxxx-user";
            else if (n === "ro.serialno") spoof = "R3CN70ZQXK";
            else if (n === "ro.boot.serialno") spoof = "R3CN70ZQXK";
            else if (n === "ro.build.product") spoof = "o1s";
            else if (n === "ro.product.board") spoof = "exynos2100";
            else if (n === "ro.boot.qemu.gltransport.name") spoof = "";
            else if (n === "ro.boot.qemu.gltransport.drawFlushInterval") spoof = "";
            else if (n.indexOf("qemu") !== -1 && n !== "ro.kernel.qemu") spoof = "";
            if (spoof !== null) { this.buf.writeUtf8String(spoof); retval.replace(ptr(spoof.length)); }
        }
    });
    console.log("[Hook] property_get hooked");
}

// === ANTI-EMULATOR: Hook access() to hide root + emulation libs ===
var access_fn = findFunc("access");
if (access_fn) {
    Interceptor.attach(access_fn, {
        onEnter: function(args) {
            var path = null;
            try { path = args[0].readCString(); } catch(e) {}
            if (path) {
                // Hide su binary in all common paths
                if (path === "/system/bin/su" || path === "/system/xbin/su" ||
                    path === "/system/sbin/su" || path === "/sbin/su" ||
                    path === "/vendor/bin/su" || path === "/vendor/xbin/su" ||
                    path === "/system/app/Superuser.apk") {
                    this.block = true;
                    send("[access] blocked: " + path);
                }
                // DON'T block EGL emulation .so files — system needs them for OpenGL ES
                // else if (path.indexOf("emulation") !== -1 && path.indexOf(".so") !== -1) {
                //     this.block = true;
                //     send("[access] blocked: " + path);
                // }
            }
        },
        onLeave: function(retval) {
            if (this.block) retval.replace(-1);  // ENOENT
        }
    });
    console.log("[Hook] access hooked (hide root + emulation libs)");
}

// === ANTI-DEBUG: openat hook for /proc/self/status redirect ===
// DISABLED: causes ART Runtime::Abort when combined with other hooks
// TracerPid is already 0 in remote device mode, so redirect is unnecessary
// Frida agent name patched in frida-server binary (app-svc-lib-64.so)
console.log("[Hook] openat/fopen hooks disabled (agent name patched in binary)");

// === ANTI-FRIDA-STRING: Hook strstr to hide "frida" in search results ===
// DISABLED: strstr hook causes ART Runtime::Abort (too invasive)
// var strstr_fn = findFunc("strstr");
// if (strstr_fn) { ... }
console.log("[Hook] strstr hook disabled (causes ART abort)");

// === ANTI-DEBUG: Hook ptrace to hide Frida attachment ===
var ptrace_fn = findFunc("ptrace");
if (ptrace_fn) {
    Interceptor.attach(ptrace_fn, {
        onEnter: function(args) {
            this.req = args[0].toInt32();
        },
        onLeave: function(retval) {
            if (this.req === 0) { // PTRACE_TRACEME
                retval.replace(0); // pretend success (not being traced)
                send("[ptrace] TRACEME -> 0 (bypass)");
            }
        }
    });
    console.log("[Hook] ptrace hooked (hide Frida attachment)");
}

// === ANTI-FRIDA-PORT: Hook connect() to block port probe (27042/27043) ===
var connect_fn = findFunc("connect");
if (connect_fn) {
    Interceptor.attach(connect_fn, {
        onEnter: function(args) {
            this.block = false;
            try {
                var sa = args[1];
                var family = sa.readU16();
                if (family === 2) { // AF_INET
                    var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                    if (port === 27042 || port === 27043 || port === 27050) {
                        this.block = true;
                        send("[connect] blocked port " + port);
                    }
                }
            } catch(e) {}
        },
        onLeave: function(retval) {
            if (this.block) retval.replace(-1);
        }
    });
    console.log("[Hook] connect hooked (block Frida port probes)");
}

// === ANTI-FRIDA-LIB: Hook dl_iterate_phdr to hide Frida agent ===
// DISABLED: causes ART Runtime::Abort when callback wrapper breaks stack unwinding
// var dl_iterate_phdr_fn = findFunc("dl_iterate_phdr");
// if (dl_iterate_phdr_fn) { ... }

// === ANTI-SELF-KILL: Block exit/kill/abort (use pause to freeze thread) ===
var pause_fn = findFunc("pause");
var do_pause = pause_fn ? new NativeFunction(pause_fn, "int", []) : null;
function freeze() { if (do_pause) while(true) do_pause(); }

var exit_fn = findFunc("exit");
if (exit_fn) Interceptor.replace(exit_fn, new NativeCallback(function(s) { send("EXIT blocked"); freeze(); }, "void", ["int"]));

var _exit_fn = findFunc("_exit");
if (_exit_fn) Interceptor.replace(_exit_fn, new NativeCallback(function(s) { send("_EXIT blocked"); freeze(); }, "void", ["int"]));

var abort_fn = findFunc("abort");
if (abort_fn) Interceptor.replace(abort_fn, new NativeCallback(function() {
    try {
        // Scan callee-saved registers for ART abort message string
        var regNames = ["x0","x19","x20","x21","x22","x23","x24","x25","x26","x27","x28"];
        var found = false;
        for (var i = 0; i < regNames.length; i++) {
            try {
                var val = this.context[regNames[i]];
                if (val.isNull()) continue;
                var s = val.readCString();
                if (s && s.length > 10 && s.length < 500) {
                    send("[ABORT " + regNames[i] + "] " + s.substring(0, 200));
                    found = true;
                }
            } catch(e) {}
        }
        if (!found) {
            // Try reading from stack
            try {
                var sp = this.context.sp;
                for (var off = 0; off < 256; off += 8) {
                    var val = sp.add(off).readPointer();
                    try {
                        var s = val.readCString();
                        if (s && s.length > 10 && s.length < 500) {
                            send("[ABORT sp+" + off + "] " + s.substring(0, 200));
                            found = true;
                            break;
                        }
                    } catch(e) {}
                }
            } catch(e) {}
        }
        send("ABORT blocked" + (found ? "" : " (no msg)"));
    } catch(e) { send("ABORT blocked (err)"); }
    freeze();
}, "void", []));

// Hook art::Runtime::Abort to read the error message
var art_abort = (typeof Module.findExportByName === "function")
    ? Module.findExportByName("libart.so", "_ZN3art7Runtime5AbortEPKc")
    : Module.findGlobalExportByName("_ZN3art7Runtime5AbortEPKc");
if (art_abort) {
    Interceptor.attach(art_abort, {
        onEnter: function(args) {
            try {
                var msg = args[1].readCString();
                send("[ART Abort] " + (msg ? msg.substring(0, 200) : "null"));
            } catch(e) { send("[ART Abort] (msg read failed)"); }
        }
    });
    console.log("[Hook] art::Runtime::Abort hooked (read message)");
}

// syscall hook DISABLED: Interceptor.replace on syscall() causes ART Runtime::Abort
// (syscall() is used internally by ART for signal handling, replacing it breaks ART)
// var syscall_fn = findFunc("syscall");
// if (syscall_fn) { ... }

var kill_fn = findFunc("kill");
if (kill_fn) Interceptor.attach(kill_fn, {
    onEnter: function(args) {
        var sig = args[1].toInt32();
        if (sig === 9 || sig === 6 || sig === 11 || sig === 15) {
            args[1] = ptr(0); // invalid signal -> kill fails, signal not delivered
            send("KILL sig=" + sig + " blocked");
        }
    }
});

var raise_fn = findFunc("raise");
if (raise_fn) Interceptor.attach(raise_fn, {
    onEnter: function(args) {
        var sig = args[0].toInt32();
        if (sig === 9 || sig === 6 || sig === 11 || sig === 15) {
            args[0] = ptr(0); // invalid signal -> raise fails
            send("RAISE sig=" + sig + " blocked");
        }
    }
});

var tgkill_fn = findFunc("tgkill");
if (tgkill_fn) Interceptor.attach(tgkill_fn, {
    onEnter: function(args) {
        var sig = args[2].toInt32();
        // Only block kill signals (SIGKILL=9, SIGABRT=6, SIGSEGV=11, SIGTERM=15)
        // Let through SIGSTOP=19 (ART GC), SIGRTMIN=33 (debuggerd backtrace)
        if (sig === 9 || sig === 6 || sig === 11 || sig === 15) {
            args[1] = ptr(0); // invalid TID -> tgkill returns ESRCH, signal not delivered
            try {
                var bt = Thread.backtrace(this.context, Backtracer.ACCURATE).map(function(a) {
                    var sym = DebugSymbol.fromAddress(a);
                    return sym.moduleName + "!" + sym.name + "@" + a;
                }).join("\n  ");
                send("TGKILL sig=" + sig + " blocked\n  " + bt);
            } catch(e) { send("TGKILL sig=" + sig + " blocked"); }
        }
    }
});

var pthread_kill_fn = findFunc("pthread_kill");
if (pthread_kill_fn) Interceptor.attach(pthread_kill_fn, {
    onEnter: function(args) {
        var sig = args[1].toInt32();
        if (sig === 9 || sig === 6 || sig === 11 || sig === 15) {
            args[1] = ptr(0); // invalid signal
            send("PTHREAD_KILL sig=" + sig + " blocked");
        }
    }
});

console.log("[Hook] Anti-kill hooks installed");

// === DEX MEMORY SCANNER (Memory.scan based: finds DEX at ANY offset) ===
// Sends DEX data via send() to Python (SELinux blocks File writes from app process)
// Packers decrypt DEX into the middle of heap ranges — the old "first 8 bytes
// of each range" check missed them entirely. Memory.scan covers everything.
var _scannedHits = {};   // addr -> true (dedupe across periodic scans)
function scanMemoryForDex() {
    var ranges = Process.enumerateRanges({
        protection: "r--",
        coalesce: false
    }).concat(Process.enumerateRanges({
        protection: "rw-",
        coalesce: false
    }));
    var dexCount = 0;

    ranges.forEach(function(range) {
        if (range.size < 4096 || range.size > 80 * 1024 * 1024) return;
        try {
            Memory.scan(range.base, range.size, "64 65 78 0a 30 33 35", {
                onMatch: function(addr, size) {
                    var key = addr.toString();
                    if (_scannedHits[key]) return;
                    _scannedHits[key] = true;
                    try {
                        var b = new Uint8Array(addr.readByteArray(8));
                        if (!(b[4]==0x30 && b[5]>=0x33 && b[5]<=0x39 && b[7]==0x00)) return;
                        var fileSize = addr.add(32).readU32();
                        // Only dump substantial DEX files. The ART runtime keeps
                        // dozens of small framework dex blobs in memory; sending
                        // all of them floods the message pipe and destabilizes
                        // the host frida client on memory-constrained machines.
                        // The packer's decrypted payload is always > 1MB.
                        if (fileSize > 1048576 && fileSize < 60 * 1024 * 1024) {
                            dexCount++;
                            // Send in 16KB chunks to avoid message size limits
                            var chunkSize = 16384;
                            var offset = 0;
                            while (offset < fileSize) {
                                var readSize = Math.min(chunkSize, fileSize - offset);
                                try {
                                    var chunk = addr.add(offset).readByteArray(readSize);
                                    if (chunk) {
                                        send({type: "dex_dump", count: dexCount, offset: offset, size: readSize, total: fileSize, tag: "scan"}, chunk);
                                        offset += readSize;
                                    } else { break; }
                                } catch(e) { break; }
                            }
                        }
                    } catch(e) {}
                },
                onError: function(e) {},
                onComplete: function() {}
            });
        } catch(e) {}
    });
    return dexCount;
}

// RPC interface for Python-controlled scanning
rpc.exports = { scan: function() { return scanMemoryForDex(); } };

// Auto-scan via setInterval as fallback (5s interval to reduce contention
// and message flooding on dex-heavy processes)
var scanTimer = setInterval(function() { scanMemoryForDex(); }, 5000);

// === JAVA HOOKS: Monitor signature verification + DEX loading ===
// Java bridge is available via frida-gadget (runs inside app process).
send("[Java] Scheduling Java hooks, Java.available=" + (typeof Java !== 'undefined' ? Java.available : 'N/A'));
function tryJavaHooks() {
    if (typeof Java !== 'undefined' && Java.available) {
        Java.perform(function() {
            send("[Java] Java.perform started");

            // Hook PackageManager.getPackageInfo to detect signature checks
            try {
                var APM = Java.use("android.app.ApplicationPackageManager");
                APM.getPackageInfo.overload("java.lang.String", "int").implementation = function(name, flags) {
                    if ((flags & 0x40) !== 0 || (flags & 0x08000000) !== 0) {
                        send("[Java] SIG check: " + name + " flags=" + flags);
                    }
                    return this.getPackageInfo(name, flags);
                };
                send("[Java] PM hooked");
            } catch(e) { send("[Java] PM hook failed: " + e); }

            // Hook DexFile constructors
            try {
                var DexFile = Java.use("dalvik.system.DexFile");
                DexFile.$init.overloads.forEach(function(ov) {
                    ov.implementation = function() {
                        send("[Java] DexFile.<init>(" + ov.argumentTypes.length + " args)");
                        return ov.apply(this, arguments);
                    };
                });
                send("[Java] DexFile hooked");
            } catch(e) { send("[Java] DexFile hook failed: " + e); }

            // Hook InMemoryDexClassLoader
            try {
                var InMemDCL = Java.use("dalvik.system.InMemoryDexClassLoader");
                InMemDCL.$init.overloads.forEach(function(ov) {
                    ov.implementation = function() {
                        send("[Java] InMemoryDexClassLoader called");
                        return ov.apply(this, arguments);
                    };
                });
                send("[Java] InMemDCL hooked");
            } catch(e) {}

            // Hook DexClassLoader
            try {
                var DexCL = Java.use("dalvik.system.DexClassLoader");
                DexCL.$init.overloads.forEach(function(ov) {
                    ov.implementation = function() {
                        send("[Java] DexClassLoader: " + arguments[0]);
                        return ov.apply(this, arguments);
                    };
                });
                send("[Java] DexCL hooked");
            } catch(e) {}

            send("[Java] All hooks installed");
        });
    } else {
        setTimeout(tryJavaHooks, 200);
    }
    }
    tryJavaHooks();
"""


def check_dynamic_environment():
    """Check if dynamic unpacking infrastructure is available."""
    has_adb = shutil.which(ADB_BIN) is not None or shutil.which("adb") is not None
    has_frida = shutil.which(FRIDA_BIN) is not None or shutil.which("frida") is not None
    
    has_device = False
    adb_cmd = shutil.which("adb") or ADB_BIN
    if has_adb and adb_cmd:
        try:
            result = subprocess.run(
                [adb_cmd, "devices"], capture_output=True, text=True, timeout=10
            )
            # Check for connected device (not "offline" or "unauthorized")
            lines = result.stdout.strip().split("\n")
            for line in lines[1:]:  # skip header
                if "device" in line and "offline" not in line and "unauthorized" not in line:
                    has_device = True
                    break
        except Exception:
            pass
    
    return {
        "adb_available": has_adb,
        "frida_available": has_frida,
        "device_connected": has_device,
        "dynamic_unpack_possible": has_adb and has_frida and has_device,
    }


def _get_device_abi(adb_cmd):
    """Get the primary ABI of the connected device."""
    try:
        result = subprocess.run(
            [adb_cmd, "shell", "getprop", "ro.product.cpu.abi"],
            capture_output=True, text=True, timeout=10,
        )
        return result.stdout.strip()
    except Exception:
        return ""


def _get_frida_version():
    """Get the installed frida version via Python module."""
    try:
        import frida
        return frida.__version__
    except Exception:
        return ""


def _download_frida_server(frida_version, abi):
    """Download and cache frida-server binary matching version + ABI.
    Returns local file path, or '' if failed.
    """
    if not frida_version or not abi:
        return ""

    frida_abi = _ABI_MAP.get(abi, abi)
    os.makedirs(_FRIDA_SERVER_CACHE_DIR, exist_ok=True)
    local_path = os.path.join(
        _FRIDA_SERVER_CACHE_DIR, f"frida-server-{frida_version}-{frida_abi}"
    )

    if os.path.isfile(local_path) and os.path.getsize(local_path) > 1_000_000:
        print(f"  [+] [DynamicUnpacker] Using cached frida-server ({frida_version}, {abi})")
        return local_path

    url = (
        f"https://github.com/frida/frida/releases/download/"
        f"{frida_version}/frida-server-{frida_version}-android-{abi}.xz"
    )
    xz_path = local_path + ".xz"
    print(f"  [*] [DynamicUnpacker] Downloading frida-server {frida_version} ({abi})...")
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "Python/3.12"})
        with urllib.request.urlopen(req, timeout=300) as resp:
            with open(xz_path, "wb") as f:
                while True:
                    chunk = resp.read(1024 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
        if not os.path.isfile(xz_path) or os.path.getsize(xz_path) < 100_000:
            print("  [!] [DynamicUnpacker] Download failed or too small")
            return ""

        with lzma.open(xz_path) as f:
            data = f.read()
        with open(local_path, "wb") as f:
            f.write(data)
        os.remove(xz_path)
        os.chmod(local_path, 0o755)
        print(
            f"  [+] [DynamicUnpacker] frida-server saved: "
            f"{os.path.getsize(local_path) // 1024} KB"
        )
        return local_path
    except Exception as e:
        print(f"  [!] [DynamicUnpacker] Download error: {e}")
        return ""


def _get_patched_frida_server_path(frida_version, abi):
    """Check if a patched frida-server binary exists (agent name renamed).
    Returns path to patched binary, or '' if not found.
    """
    frida_abi = _ABI_MAP.get(abi, abi)
    patched_path = os.path.join(
        _FRIDA_SERVER_CACHE_DIR, f"frida-server-{frida_version}-{frida_abi}-patched"
    )
    if os.path.isfile(patched_path) and os.path.getsize(patched_path) > 1_000_000:
        return patched_path
    return ""


def _is_frida_server_responsive(adb_cmd):
    """Check if frida-server is already running on device.
    Tries to connect to the frida-server port via adb forward.
    """
    try:
        # Set up adb forward
        subprocess.run(
            [adb_cmd, "forward", f"tcp:{FRIDA_SERVER_PORT}", f"tcp:{FRIDA_SERVER_PORT}"],
            capture_output=True, timeout=10,
        )
        import frida as _frida
        mgr = _frida.get_device_manager()
        device = mgr.add_remote_device(f"127.0.0.1:{FRIDA_SERVER_PORT}")
        # Try to enumerate processes — if this succeeds, server is responsive
        device.enumerate_processes()
        return True
    except Exception:
        # Fallback: check for frida-server process
        try:
            result = subprocess.run(
                [adb_cmd, "shell", "ps", "-A"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[-1] == "fs":
                    return True
        except Exception:
            pass
        return False


def _deploy_frida_server(adb_cmd):
    """Deploy and start frida-server on the device if not already running.
    Returns True if frida-server is (or was made) running.
    """
    if _is_frida_server_responsive(adb_cmd):
        print("  [+] [DynamicUnpacker] frida-server already running")
        return True

    frida_version = _get_frida_version()
    abi = _get_device_abi(adb_cmd)

    if not frida_version:
        print("  [!] [DynamicUnpacker] Could not determine frida version")
        return False
    if not abi:
        print("  [!] [DynamicUnpacker] Could not determine device ABI")
        return False

    print(f"  [*] [DynamicUnpacker] frida={frida_version}, device ABI={abi}")

    local_path = _get_patched_frida_server_path(frida_version, abi)
    if local_path:
        print(f"  [+] [DynamicUnpacker] Using patched frida-server (agent name hidden)")
    else:
        local_path = _download_frida_server(frida_version, abi)
    if not local_path:
        return False

    try:
        subprocess.run([adb_cmd, "root"], capture_output=True, timeout=10)
        time.sleep(1)
    except Exception:
        pass

    subprocess.run(
        [adb_cmd, "shell", "pkill", "-f", "frida-server"],
        capture_output=True, timeout=10,
    )
    subprocess.run(
        [adb_cmd, "shell", "pkill", "-f", "/data/local/tmp/fs"],
        capture_output=True, timeout=10,
    )

    print("  [*] [DynamicUnpacker] Pushing frida-server to device (renamed to 'fs')...")
    try:
        subprocess.run(
            [adb_cmd, "push", local_path, FRIDA_SERVER_DEVICE_PATH],
            capture_output=True, timeout=120,
        )
        subprocess.run(
            [adb_cmd, "shell", "chmod", "755", FRIDA_SERVER_DEVICE_PATH],
            capture_output=True, timeout=10,
        )
    except Exception as e:
        print(f"  [!] [DynamicUnpacker] Push failed: {e}")
        return False

    print("  [*] [DynamicUnpacker] Starting frida-server on device...")
    try:
        subprocess.Popen(
            [adb_cmd, "shell", FRIDA_SERVER_DEVICE_PATH, "-l", f"0.0.0.0:{FRIDA_SERVER_PORT}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(3)

        if _is_frida_server_responsive(adb_cmd):
            print("  [+] [DynamicUnpacker] frida-server is running (as 'fs')")
            return True
        else:
            print("  [!] [DynamicUnpacker] frida-server not found in process list")
            return False
    except Exception as e:
        print(f"  [!] [DynamicUnpacker] Start failed: {e}")
        return False


def _inject_frida_and_dump(adb_cmd, frida_cmd, package_name, script_path, output_dir):
    """Inject Frida script via Python API. Uses remote device mode on non-standard port.
    Handles chunked DEX data sent via send() (SELinux blocks File writes from app process).
    """
    with open(script_path) as f:
        script_code = f.read()

    try:
        import frida as _frida
    except ImportError:
        print("  [!] [DynamicUnpacker] frida Python module not available")
        return []

    # Set up adb port forwarding and connect via remote device mode
    subprocess.run(
        [adb_cmd, "forward", f"tcp:{FRIDA_SERVER_PORT}", f"tcp:{FRIDA_SERVER_PORT}"],
        capture_output=True, timeout=10,
    )
    try:
        mgr = _frida.get_device_manager()
        device = mgr.add_remote_device(f"127.0.0.1:{FRIDA_SERVER_PORT}")
    except Exception as e:
        print(f"  [!] [DynamicUnpacker] Cannot connect to device: {e}")
        return []

    # Collect chunked DEX data from send() messages
    dex_chunks = {}  # {dex_idx: {"total": int, "chunks": {offset: data}}}

    def on_message(msg, data):
        if msg.get("type") == "send":
            payload = msg["payload"]
            if isinstance(payload, dict) and payload.get("type") == "dex_dump":
                idx = payload["count"]
                offset = payload["offset"]
                if idx not in dex_chunks:
                    dex_chunks[idx] = {"total": payload["total"], "chunks": {}}
                dex_chunks[idx]["chunks"][offset] = data
            elif isinstance(payload, str):
                print(f"      [frida] {payload[:200]}")
        elif msg.get("type") == "error":
            print(f"      [frida-err] {msg.get('description', '')[:200]}")

    # Strategy: Spawn + auto-scan (setInterval in JS handles scanning every 1s)
    print("  [*] [DynamicUnpacker] Spawn + auto-scan...")
    try:
        pid = device.spawn([package_name])
        session = device.attach(pid)

        script = session.create_script(script_code)
        script.on("message", on_message)
        script.load()
        device.resume(pid)

        # Wait for packer to decrypt DEX (auto-scan runs via setInterval)
        scan_time = min(DYNAMIC_UNPACKING_TIMEOUT, 60)
        for i in range(scan_time):
            if session.is_detached:
                print(f"      [session] detached at {i}s")
                break
            time.sleep(1)

        try:
            session.detach()
        except Exception:
            pass
        print(f"  [+] [DynamicUnpacker] Spawn mode done ({scan_time}s)")
    except Exception as e:
        print(f"  [!] [DynamicUnpacker] Spawn mode error: {e}")

    # Reassemble chunked DEX data into files
    dumped_dex_paths = []
    for idx in sorted(dex_chunks.keys()):
        info = dex_chunks[idx]
        total = info["total"]
        chunks = info["chunks"]
        received = sum(len(c) for c in chunks.values())
        if received < 100:
            continue
        if received < total:
            print(f"  [!] DEX #{idx}: incomplete ({received}/{total} bytes)")

        # Reassemble in order
        dex_data = bytearray(total)
        for offset, chunk_data in sorted(chunks.items()):
            dex_data[offset:offset + len(chunk_data)] = chunk_data

        # Validate DEX magic
        if dex_data[:4] == b'dex\n':
            dex_path = os.path.join(output_dir, f"dumped_{idx}.dex")
            with open(dex_path, "wb") as f:
                f.write(bytes(dex_data[:received]))
            dumped_dex_paths.append(dex_path)
            print(f"  [+] DEX #{idx}: {received} bytes saved")

    return dumped_dex_paths


def _start_emulator_by_arch(arch):
    """Start the appropriate emulator based on detected architecture.

    macOS (original design):
      ARM32 → unpack_avd_32 (API 25 armeabi-v7a, has 32-bit support)
      ARM64/unknown → unpack_avd (API 33 arm64-v8a, current setup)

    Windows x86_64 hosts: the Android emulator only ships x86_64 images, so
    BOTH ARM32 and ARM64 APKs run on the same x86_64 AVD via native bridge
    (libndk ARM translation, supported by API 30+ google_apis images).

    Returns True if a device is available after this call.
    """
    env = check_dynamic_environment()
    if env["device_connected"]:
        return True

    if not env["adb_available"]:
        return False

    emulator_cmd = shutil.which("emulator") or EMULATOR_BIN
    if not emulator_cmd or not os.path.isfile(emulator_cmd):
        for exe_name in ("emulator.exe", "emulator"):
            sdk_emulator = os.path.join(ANDROID_SDK_ROOT, "emulator", exe_name)
            if os.path.isfile(sdk_emulator):
                emulator_cmd = sdk_emulator
                break

    if not emulator_cmd or not os.path.isfile(emulator_cmd):
        print("  [!] [DynamicUnpacker] No emulator binary found")
        return False

    if sys.platform == "win32":
        # 32-bit x86 AVD (API 28 + ndk_translation) handles every APK arch:
        # ARM32/ARM64 code is translated, x86 runs natively.
        avd_name = EMULATOR_AVD_NAME
        qemu_name = "qemu-system-i386"
    elif arch in ("arm32", "both"):
        avd_name = EMULATOR_AVD_32_NAME
        qemu_name = "qemu-system-armel"
    else:
        avd_name = EMULATOR_AVD_NAME
        qemu_name = "qemu-system-aarch64"

    global _emulator_started_by_pipeline
    print(f"  [*] [DynamicUnpacker] Starting emulator: {avd_name} (arch={arch}, qemu={qemu_name})")
    try:
        subprocess.Popen(
            [emulator_cmd, "-avd", avd_name, "-no-window",
             "-no-audio", "-no-boot-anim", "-gpu", "swiftshader_indirect",
             "-no-snapshot", "-memory", "1536"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        adb_cmd = shutil.which("adb") or ADB_BIN
        print("  [*] [DynamicUnpacker] Waiting for emulator to boot...")
        for i in range(90):
            time.sleep(2)
            result = subprocess.run(
                [adb_cmd, "shell", "getprop", "sys.boot_completed"],
                capture_output=True, text=True, timeout=5,
            )
            if "1" in result.stdout:
                print("  [+] [DynamicUnpacker] Emulator booted")
                _emulator_started_by_pipeline = True
                return True
        print("  [!] [DynamicUnpacker] Emulator boot timeout")
        return False
    except Exception as e:
        print(f"  [!] [DynamicUnpacker] Emulator start error: {e}")
        return False


def _connect_gadget_and_dump(adb_cmd, package_name, script_code, output_dir):
    """Connect to frida-gadget inside the running app process.
    
    The gadget was injected into the APK and is running in 'listen + wait' mode.
    We connect via adb forward, load the DEX dump script, and resume the app.
    The app was paused by the gadget — after resume, the packer runs and
    decrypts DEX. Our scanner finds it in memory and sends it back via send().
    
    Returns list of dumped DEX file paths.
    """
    try:
        import frida as _frida
    except ImportError:
        print("  [!] [DynamicUnpacker] frida Python module not available")
        return []

    subprocess.run(
        [adb_cmd, "forward", f"tcp:{GADGET_PORT}", f"tcp:{GADGET_PORT}"],
        capture_output=True, timeout=10,
    )

    print(f"  [*] [DynamicUnpacker] Connecting to gadget at 127.0.0.1:{GADGET_PORT}...")
    try:
        mgr = _frida.get_device_manager()
        device = mgr.add_remote_device(f"127.0.0.1:{GADGET_PORT}")
    except Exception as e:
        print(f"  [!] [DynamicUnpacker] Cannot connect to gadget: {e}")
        return []

    dex_chunks = {}

    def on_message(msg, data):
        if msg.get("type") == "send":
            payload = msg["payload"]
            if isinstance(payload, dict) and payload.get("type") == "dex_dump":
                idx = payload["count"]
                offset = payload["offset"]
                if idx not in dex_chunks:
                    dex_chunks[idx] = {"total": payload["total"], "chunks": {}}
                dex_chunks[idx]["chunks"][offset] = data
            elif isinstance(payload, str):
                print(f"      [frida] {payload[:200]}")
        elif msg.get("type") == "error":
            print(f"      [frida-err] {msg.get('description', '')[:200]}")

    print("  [*] [DynamicUnpacker] Finding gadget process...")
    target_pid = None
    for _ in range(30):
        try:
            for proc in device.enumerate_processes():
                # In gadget mode the process is usually named "Gadget"; the
                # package name may also show up. Match either.
                if (package_name in proc.name
                        or "frida" in proc.name.lower()
                        or proc.name.strip().lower() == "gadget"):
                    target_pid = proc.pid
                    print(f"  [+] [DynamicUnpacker] Found process: {proc.name} (PID={target_pid})")
                    break
            if target_pid:
                break
        except Exception:
            pass
        time.sleep(1)

    if not target_pid:
        print("  [!] [DynamicUnpacker] Gadget process not found")
        return []

    try:
        session = device.attach(target_pid)
        script = session.create_script(script_code)
        script.on("message", on_message)
        script.load()
        print("  [+] [DynamicUnpacker] Script loaded, resuming app...")

        try:
            device.resume(target_pid)
        except Exception:
            pass

        scan_time = min(DYNAMIC_UNPACKING_TIMEOUT, 60)
        for i in range(scan_time):
            if session.is_detached:
                print(f"      [session] detached at {i}s")
                break
            time.sleep(1)

        # IMPORTANT: assemble & save DEX files BEFORE session.detach().
        # After a large message volume (hundreds of MB of chunks) the frida
        # client's detach() can hang indefinitely on Windows — saving first
        # guarantees the data is on disk even if detach blocks.
        dumped_dex_paths = []
        for idx in sorted(dex_chunks.keys()):
            info = dex_chunks[idx]
            total = info["total"]
            chunks = info["chunks"]
            received = sum(len(c) for c in chunks.values())
            if received < 100:
                continue
            if received < total:
                print(f"  [!] DEX #{idx}: incomplete ({received}/{total} bytes)")

            dex_data = bytearray(total)
            for offset, chunk_data in sorted(chunks.items()):
                dex_data[offset:offset + len(chunk_data)] = chunk_data

            if dex_data[:4] == b'dex\n':
                dex_path = os.path.join(output_dir, f"dumped_{idx}.dex")
                with open(dex_path, "wb") as f:
                    f.write(bytes(dex_data[:received]))
                dumped_dex_paths.append(dex_path)
                print(f"  [+] DEX #{idx}: {received} bytes saved")

        try:
            session.detach()
        except Exception:
            pass
        print(f"  [+] [DynamicUnpacker] Done ({scan_time}s)")
    except Exception as e:
        print(f"  [!] [DynamicUnpacker] Script error: {e}")
        return []

    return dumped_dex_paths


def _acquire_adb_lock():
    """Acquire an exclusive lock so only one agent uses ADB/emulator at a time.
    POSIX: fcntl.flock. Windows: msvcrt.locking."""
    lock = None
    try:
        f = open(ADB_LOCK_FILE, "a+")
        if sys.platform == "win32":
            import msvcrt
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        lock = f
    except Exception:
        try:
            f.close()
        except Exception:
            pass
    return lock


def _release_adb_lock(lock):
    if lock is None:
        return
    try:
        if sys.platform == "win32":
            import msvcrt
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()
    except Exception:
        pass


def try_dynamic_unpack(apk_path, packing_assessment, output_dir=None):
    """Entry point: serialize dynamic unpacks across parallel agents via ADB lock,
    then delegate to the real implementation."""
    lock = _acquire_adb_lock()
    try:
        return _try_dynamic_unpack_impl(apk_path, packing_assessment, output_dir)
    finally:
        _release_adb_lock(lock)


def _try_dynamic_unpack_impl(apk_path, packing_assessment, output_dir=None):
    """Main entry: attempt dynamic DEX dumping via Frida-gadget.
    
    Uses frida-gadget injection (not frida-server) for Java bridge support.
    Automatically detects APK architecture and selects the right emulator
    (ARM32 → API 25 armeabi-v7a AVD, ARM64 → API 33 arm64-v8a AVD).
    
    Returns list of dumped DEX file paths (empty if failed).
    """
    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="dynamic_dex_")

    # Step 1: Detect APK architecture
    from gadget_injector import detect_apk_architecture, inject_gadget
    arch = detect_apk_architecture(apk_path)
    packer_name = packing_assessment.get("packer_name", "unknown")
    print(f"  [*] [DynamicUnpacker] Starting: packer={packer_name}, arch={arch}")

    # Step 2: Start appropriate emulator
    if not _start_emulator_by_arch(arch):
        print("  [!] [DynamicUnpacker] Emulator not available")
        return []

    adb_cmd = shutil.which("adb") or ADB_BIN

    # Step 3: Get package name
    package_name = _get_package_name(apk_path)
    if not package_name:
        print("  [!] [DynamicUnpacker] Could not determine package name")
        return []
    print(f"  [+] [DynamicUnpacker] Package: {package_name}")

    # Step 4: Inject frida-gadget into APK
    # The gadget .so is loaded by the app process, so its ABI must match the
    # EMULATOR (host-side) ABI, not the APK's original ABI:
    #   - Windows x86 hosts run a 32-bit x86 emulator image (API 28 google_apis
    #     x86 with ndk_translation for ARM apps) → gadget 'x86'
    #   - macOS ARM hosts run arm64/arm32 AVDs → gadget matches APK arch
    # ARM app code itself is translated by ndk_translation; the gadget still
    # gets full Java VM access through the Java bridge.
    if sys.platform == "win32":
        gadget_arch = "x86"
    else:
        gadget_arch = "arm32" if arch in ("arm32", "both") else "arm64"
    print(f"  [*] [DynamicUnpacker] Injecting frida-gadget ({gadget_arch})...")
    gadget_apk = inject_gadget(apk_path, gadget_arch, output_dir)
    if not gadget_apk:
        print("  [!] [DynamicUnpacker] Gadget injection failed — aborting")
        return []

    # Step 5: Install gadget-injected APK
    print("  [*] [DynamicUnpacker] Installing gadget APK...")
    try:
        result = subprocess.run(
            [adb_cmd, "install", "-r", "-t", gadget_apk],
            capture_output=True, text=True, timeout=120,
        )
        if "Success" not in result.stdout:
            err = (result.stderr or "").strip() or result.stdout.strip()
            print(f"  [!] [DynamicUnpacker] Install failed: {err}")
            return []
    except Exception as e:
        print(f"  [!] [DynamicUnpacker] Install error: {e}")
        return []

    # Step 6: Start app (gadget loads, app pauses in 'wait' mode)
    print("  [*] [DynamicUnpacker] Starting app (gadget will pause app)...")
    main_activity = _aapt_badging_field(
        apk_path, r"launchable-activity:\s*name='([^']+)'")
    if main_activity:
        # aapt returns a fully-qualified or relative name; resolve relative
        if main_activity.startswith("."):
            component = package_name + main_activity
        elif "." not in main_activity:
            component = package_name + "." + main_activity
        else:
            component = main_activity
        if not component.startswith(package_name + "/") and "/" not in component:
            component = package_name + "/" + component
    else:
        short = _get_main_activity_name(apk_path)
        component = package_name + "/." + short
    print(f"  [*] [DynamicUnpacker] Launching component: {component}")
    subprocess.run(
        [adb_cmd, "shell", "am", "start", "-n", component],
        capture_output=True, timeout=15,
    )
    time.sleep(3)

    # Step 7: Connect to gadget and dump DEX
    script_code = FRIDA_DEX_DUMP_SCRIPT
    print(f"  [*] [DynamicUnpacker] Connecting to gadget (timeout={DYNAMIC_UNPACKING_TIMEOUT}s)...")
    dumped_dex_paths = _connect_gadget_and_dump(
        adb_cmd, package_name, script_code, output_dir
    )

    if dumped_dex_paths:
        print(f"  [+] [DynamicUnpacker] Collected {len(dumped_dex_paths)} DEX files")
    else:
        print("  [!] [DynamicUnpacker] No DEX files dumped")

    # Cleanup: uninstall APK
    subprocess.run([adb_cmd, "uninstall", package_name], capture_output=True, timeout=30)

    return dumped_dex_paths


def _get_main_activity_name(apk_path):
    """Get the main activity name (without package prefix) from the APK."""
    try:
        from androguard.core.apk import APK
        apk = APK(apk_path, skip_analysis=True)
        main = apk.get_main_activity()
        if main:
            if "." in main and "/" not in main:
                return main.split(".")[-1]
            return main
    except Exception:
        pass
    # aapt fallback: "launchable-activity: name='com.foo.Bar'"
    act = _aapt_badging_field(apk_path, r"launchable-activity:\s*name='([^']+)'")
    if act:
        if "/" in act:
            return act.split("/")[-1]
        return act.split(".")[-1] if "." in act else act
    return "MainActivity"


def _get_package_name(apk_path):
    """Extract package name from APK using androguard, pyaxmlparser, aapt, or jadx MCP."""
    try:
        from androguard.core.apk import APK
        apk = APK(apk_path, skip_analysis=True)
        pkg = apk.get_package()
        if pkg:
            return pkg
    except Exception:
        pass
    try:
        import pyaxmlparser
        apk = pyaxmlparser.APK(apk_path)
        if apk.package:
            return apk.package
    except Exception:
        pass
    # aapt fallback (handles packers whose manifest confuses androguard, e.g. Legu)
    pkg = _aapt_badging_field(apk_path, r"package:\s*name='([^']+)'")
    if pkg:
        return pkg
    try:
        from jadx_extractor import get_android_manifest
        import re
        manifest = get_android_manifest()
        m = re.search(r'package="([^"]+)"', manifest)
        return m.group(1) if m else ""
    except Exception:
        return ""


def _aapt_badging_field(apk_path, pattern):
    """Run aapt dump badging and extract the first regex group (or '')."""
    import re as _re
    import shutil as _sh
    aapt = _sh.which("aapt")
    if not aapt:
        for root in (os.environ.get("ANDROID_SDK_ROOT"), r"D:\Android\sdk"):
            if not root:
                continue
            bt = os.path.join(root, "build-tools")
            if not os.path.isdir(bt):
                continue
            for v in sorted(os.listdir(bt), reverse=True):
                cand = os.path.join(bt, v, "aapt.exe")
                if os.path.isfile(cand):
                    aapt = cand
                    break
            if aapt:
                break
    if not aapt:
        return ""
    try:
        result = subprocess.run(
            [aapt, "dump", "badging", apk_path],
            capture_output=True, text=True, timeout=30,
        )
        m = _re.search(pattern, result.stdout or "")
        return m.group(1) if m else ""
    except Exception:
        return ""


def _collect_dumped_dex(adb_cmd, output_dir):
    """Pull dumped DEX files from device via ADB."""
    dumped = []
    
    # List files in dump directory
    try:
        result = subprocess.run(
            [adb_cmd, "shell", "ls", "/data/local/tmp/dumped_dex/"],
            capture_output=True, text=True, timeout=10,
        )
        files = result.stdout.strip().split("\n")
    except Exception:
        return []

    for f in files:
        f = f.strip()
        if not f or not f.endswith(".dex"):
            continue
        device_path = f"/data/local/tmp/dumped_dex/{f}"
        local_path = os.path.join(output_dir, f)
        
        try:
            subprocess.run(
                [adb_cmd, "pull", device_path, local_path],
                capture_output=True, timeout=30,
            )
            if os.path.isfile(local_path) and os.path.getsize(local_path) > 100:
                # Validate DEX magic
                with open(local_path, "rb") as f:
                    header = f.read(8)
                if header[:3] == b'dex':
                    dumped.append(local_path)
                else:
                    os.remove(local_path)  # not a valid DEX
        except Exception:
            pass

    # Cleanup device dump directory
    subprocess.run([adb_cmd, "shell", "rm", "-rf", "/data/local/tmp/dumped_dex/"],
                    capture_output=True, timeout=10)

    return dumped


def start_emulator_if_needed():
    """Start a headless Android emulator if no device is connected.
    Returns True if a device is available after this call.
    """
    env = check_dynamic_environment()
    if env["device_connected"]:
        return True

    if not env["adb_available"]:
        return False

    # Try to start emulator
    emulator_cmd = shutil.which("emulator") or EMULATOR_BIN
    if not emulator_cmd or not os.path.isfile(emulator_cmd):
        # Try Android SDK path
        sdk_emulator = os.path.join(ANDROID_SDK_ROOT, "emulator", "emulator")
        if os.path.isfile(sdk_emulator):
            emulator_cmd = sdk_emulator

    if not emulator_cmd or not os.path.isfile(emulator_cmd):
        print("  [!] [DynamicUnpacker] No emulator binary found")
        return False

    print(f"  [*] [DynamicUnpacker] Starting emulator: {EMULATOR_AVD_NAME}")
    global _emulator_started_by_pipeline
    try:
        # Start emulator in background (headless)
        subprocess.Popen(
            [emulator_cmd, "-avd", EMULATOR_AVD_NAME, "-no-window",
             "-no-audio", "-no-boot-anim", "-gpu", "swiftshader_indirect"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        # Wait for boot (up to 180 seconds)
        adb_cmd = shutil.which("adb") or ADB_BIN
        print("  [*] [DynamicUnpacker] Waiting for emulator to boot...")
        for i in range(90):  # 90 iterations × 2s = 180s max
            time.sleep(2)
            result = subprocess.run(
                [adb_cmd, "shell", "getprop", "sys.boot_completed"],
                capture_output=True, text=True, timeout=5,
            )
            if "1" in result.stdout:
                print("  [+] [DynamicUnpacker] Emulator booted")
                _emulator_started_by_pipeline = True
                return True
        print("  [!] [DynamicUnpacker] Emulator boot timeout")
        return False
    except Exception as e:
        print(f"  [!] [DynamicUnpacker] Emulator start error: {e}")
        return False


def stop_emulator_if_started(adb_cmd=None):
    """Shut down the emulator if it was started by this pipeline.
    Safe to call multiple times; no-op if emulator was externally started.
    """
    global _emulator_started_by_pipeline
    if not _emulator_started_by_pipeline:
        return False

    if adb_cmd is None:
        adb_cmd = shutil.which("adb") or ADB_BIN

    print("  [*] [DynamicUnpacker] Shutting down emulator (started by pipeline)...")
    try:
        subprocess.run(
            [adb_cmd, "emu", "kill"],
            capture_output=True, timeout=15,
        )
        time.sleep(2)
        # Verify it's gone
        result = subprocess.run(
            [adb_cmd, "devices"],
            capture_output=True, text=True, timeout=10,
        )
        if "emulator" not in result.stdout:
            print("  [+] [DynamicUnpacker] Emulator shut down successfully")
        else:
            # Still running — force kill (both ARM32 and ARM64 QEMU)
            subprocess.run(
                [adb_cmd, "shell", "killall", "-9", "qemu-system-aarch64"],
                capture_output=True, timeout=10,
            )
            subprocess.run(
                [adb_cmd, "shell", "killall", "-9", "qemu-system-armel"],
                capture_output=True, timeout=10,
            )
            print("  [+] [DynamicUnpacker] Emulator force-killed")
    except Exception as e:
        print(f"  [!] [DynamicUnpacker] Emulator shutdown error: {e}")

    _emulator_started_by_pipeline = False
    return True
