/**
 * JNI Tracer — Sentinel
 * Low-noise JNI tracing: FindClass, RegisterNatives, method/field lookups.
 * High-volume call-family and string tracing stay off by default.
 *
 * Source: DragonJAR/Android-Pentesting-Skill (Apache 2.0), adapted for Sentinel.
 *
 * Usage:
 *   frida -U -f com.target.app -l jni-tracer.js
 */
'use strict';

const CONFIG = {
    TARGET_LIB_SUBSTRINGS: [],
    CLASS_EXCLUDE_PREFIXES: ['android/','androidx/','dalvik/','java/','javax/','kotlin/','sun/'],
    TRACE_CLASS_LOOKUPS: true,
    TRACE_METHOD_LOOKUPS: true,
    TRACE_FIELD_LOOKUPS: true,
    TRACE_REGISTER_NATIVES: true,
    TRACE_STRING_BRIDGES: false,
    TRACE_CALL_FAMILY: false,
    STACK_ON_MATCH: false,
    MAX_STRING_LENGTH: 180,
};

const JNI_INDEX = {
    FindClass: 6, GetMethodID: 33, CallObjectMethod: 34, CallBooleanMethod: 37,
    CallIntMethod: 49, CallLongMethod: 52, CallVoidMethod: 61, GetFieldID: 94,
    GetStaticMethodID: 113, CallStaticObjectMethod: 114, CallStaticBooleanMethod: 117,
    CallStaticIntMethod: 129, CallStaticLongMethod: 132, CallStaticVoidMethod: 141,
    GetStaticFieldID: 144, NewStringUTF: 167, GetStringUTFChars: 169, RegisterNatives: 215,
};

const classCache = {}, methodCache = {}, fieldCache = {}, installed = {};

const truncate = v => { const s = String(v ?? '<null>'); return s.length <= CONFIG.MAX_STRING_LENGTH ? s : s.slice(0, CONFIG.MAX_STRING_LENGTH) + '…'; };
const includesAny = (v, ns) => ns.some(n => String(v).toLowerCase().includes(String(n).toLowerCase()));
const matchesMod = m => !CONFIG.TARGET_LIB_SUBSTRINGS.length || includesAny(m, CONFIG.TARGET_LIB_SUBSTRINGS);
const matchesCls = c => c ? !CONFIG.CLASS_EXCLUDE_PREFIXES.some(p => String(c).startsWith(p)) : true;
const safeStr = p => { try { return p && !p.isNull() ? p.readCString() : null; } catch { return null; } };
const pkey = p => { try { return p && !p.isNull() ? p.toString() : null; } catch { return null; } };
const callerOf = ra => { try { const m = Process.findModuleByAddress(ra); return m ? `${m.name}+${ra.sub(m.base)}` : String(ra); } catch { return '<?>'; } };
const env = () => { try { return Java.vm.tryGetEnv(); } catch { return null; } };
const resolveCls = p => { const k = pkey(p); if (k && classCache[k]) return classCache[k]; try { const n = env()?.getClassName(p); if (n && k) classCache[k] = n; return n; } catch { return null; } };

function hook(name, idx, cbs) {
    const envH = Java.vm.getEnv().handle;
    const addr = envH.readPointer().add(idx * Process.pointerSize).readPointer();
    const k = pkey(addr); if (!k || installed[k]) return; installed[k] = name;
    Interceptor.attach(addr, {
        onEnter(args) {
            this.ci = callerOf(this.returnAddress);
            this.ok = matchesMod(Process.findModuleByAddress(this.returnAddress)?.name);
            this.args = args;
            if (this.ok && cbs.onEnter) cbs.onEnter.call(this, args);
        },
        onLeave(ret) { if (this.ok && cbs.onLeave) cbs.onLeave.call(this, ret); }
    });
}

function installHooks() {
    // FindClass
    hook('FindClass', JNI_INDEX.FindClass, {
        onEnter(a) { this.cls = safeStr(a[1]); if (!matchesCls(this.cls)) this.ok = false; },
        onLeave(r) { if (r && !r.isNull() && this.cls) classCache[pkey(r)] = this.cls; send({tag:'jni',fn:'FindClass',class:this.cls,caller:this.ci}); }
    });
    // GetMethodID / GetStaticMethodID
    for (const [n, idx, st] of [['GetMethodID',JNI_INDEX.GetMethodID,false],['GetStaticMethodID',JNI_INDEX.GetStaticMethodID,true]]) {
        hook(n, idx, {
            onEnter(a) { this.cls = resolveCls(a[1])||pkey(a[1]); this.mn = safeStr(a[2]); this.sig = safeStr(a[3]); if (!matchesCls(this.cls)) this.ok=false; },
            onLeave(r) { if (r) { const k=pkey(r); if(k) methodCache[k]={cls:this.cls,name:this.mn,sig:this.sig,static:st}; } send({tag:'jni',fn:n,class:this.cls,method:this.mn,sig:this.sig,caller:this.ci}); }
        });
    }
    // GetFieldID / GetStaticFieldID
    for (const [n, idx] of [['GetFieldID',JNI_INDEX.GetFieldID],['GetStaticFieldID',JNI_INDEX.GetStaticFieldID]]) {
        hook(n, idx, {
            onEnter(a) { this.cls = resolveCls(a[1])||pkey(a[1]); this.fn2 = safeStr(a[2]); this.sig = safeStr(a[3]); if (!matchesCls(this.cls)) this.ok=false; },
            onLeave(r) { send({tag:'jni',fn:n,class:this.cls,field:this.fn2,sig:this.sig,caller:this.ci}); }
        });
    }
    // RegisterNatives
    hook('RegisterNatives', JNI_INDEX.RegisterNatives, {
        onEnter(a) { this.cls = resolveCls(a[1])||pkey(a[1]); this.meths = a[2]; this.cnt = a[3].toInt32(); if (!matchesCls(this.cls)) this.ok=false; },
        onLeave() {
            for (let i = 0; i < this.cnt; i++) {
                const e = this.meths.add(i * Process.pointerSize * 3);
                const nm = safeStr(e.readPointer()); const sg = safeStr(e.add(Process.pointerSize).readPointer());
                const fp = e.add(Process.pointerSize*2).readPointer(); const mod = Process.findModuleByAddress(fp)?.name || '<unknown>';
                if (!matchesMod(mod)) continue;
                send({tag:'jni',fn:'RegisterNatives',class:this.cls,method:nm,sig:sg,module:mod,addr:fp.toString()});
            }
        }
    });
    send({tag:'jni',fn:'init',status:'JNI tracer loaded'});
}

Java.perform(installHooks);
