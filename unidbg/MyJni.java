import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;

public class MyJni extends AbstractJni {

    static final String PKG = "com.hottagames.yh.laohu";
    static void log(String s){ System.out.println("[JNI] " + s); }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> obj, String m, VarArg va) {
        String a0 = null;
        try { DvmObject<?> o = va.getObjectArg(0); a0 = o != null ? String.valueOf(o.getValue()) : null; } catch (Throwable t) {}
        log("callObject " + (obj != null ? obj.getObjectType() : "?") + "." + m + "(" + (a0 != null ? a0 : va) + ")");
        if ("getClassLoader".equals(m)) return vm.resolveClass("dalvik/system/BaseDexClassLoader").newObject(null);
        if ("loadClass".equals(m)) { log("  *** VM loadClass: " + a0); return a0 != null ? vm.resolveClass(a0.replace('.', '/')) : null; }
        if ("getName".equals(m)) return new StringObject(vm, String.valueOf(obj != null ? obj.getObjectType() : "?"));
        if ("getPackageName".equals(m)) return new StringObject(vm, PKG);
        if ("getFilesDir".equals(m)) return new StringObject(vm, "/data/data/" + PKG + "/files");
        if ("getCacheDir".equals(m)) return new StringObject(vm, "/data/data/" + PKG + "/cache");
        if ("getPackageCodePath".equals(m)) return new StringObject(vm, "/data/app/" + PKG + "/base.apk");
        if ("getDeviceId".equals(m)) return new StringObject(vm, "000000000000000");
        if ("getSubscriberId".equals(m)) return new StringObject(vm, "000000000000000");
        if ("getString".equals(m)) return new StringObject(vm, "");
        if ("getText".equals(m)) return new StringObject(vm, "");
        if ("toString".equals(m)) return new StringObject(vm, PKG);
        if ("getBytes".equals(m)) { String s=String.valueOf(obj.getValue()); byte[] bb; try{ bb=s.getBytes("GB2312"); }catch(Exception e){ bb=s.getBytes(); } return new com.github.unidbg.linux.android.dvm.array.ByteArray(vm, bb); }
        return null;
    }
    @Override public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> obj, DvmMethod dm, VarArg va) {
        return callObjectMethod(vm, obj, dm != null ? dm.getMethodName() : "?", va);
    }

    @Override public int callIntMethod(BaseVM vm, DvmObject<?> obj, String m, VarArg va){ log("callInt "+obj.getObjectType()+"."+m+"("+va+")"); return 0; }
    @Override public boolean callBooleanMethod(BaseVM vm, DvmObject<?> obj, String m, VarArg va){ log("callBool "+obj.getObjectType()+"."+m+"("+va+")"); return false; }
    @Override public long callLongMethod(BaseVM vm, DvmObject<?> obj, String m, VarArg va){ log("callLong "+obj.getObjectType()+"."+m+"("+va+")"); return 0L; }
    @Override public void callVoidMethod(BaseVM vm, DvmObject<?> obj, String m, VarArg va){ log("callVoid "+obj.getObjectType()+"."+m+"("+va+")"); }

    @Override public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass clazz, String m, VarArg va){ log("callStaticObject "+clazz.getClassName()+"."+m+"("+va+")"); return null; }
    @Override public int callStaticIntMethod(BaseVM vm, DvmClass clazz, String m, VarArg va){ log("callStaticInt "+clazz.getClassName()+"."+m+"("+va+")"); return 0; }
    @Override public boolean callStaticBooleanMethod(BaseVM vm, DvmClass clazz, String m, VarArg va){ log("callStaticBool "+clazz.getClassName()+"."+m+"("+va+")"); return false; }
    @Override public long callStaticLongMethod(BaseVM vm, DvmClass clazz, String m, VarArg va){ log("callStaticLong "+clazz.getClassName()+"."+m+"("+va+")"); return 0L; }
    @Override public void callStaticVoidMethod(BaseVM vm, DvmClass clazz, String m, VarArg va){ log("*** callStaticVoid "+clazz.getClassName()+"."+m+"("+va+")"); }

    @Override public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass clazz, String f){ log("getStaticObjectField "+clazz.getClassName()+"."+f); return null; }
    @Override public int getStaticIntField(BaseVM vm, DvmClass clazz, String f){ log("getStaticIntField "+clazz.getClassName()+"."+f); return 0; }

    @Override public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> obj, String f){
        log("getObjectField "+obj.getObjectType()+"."+f);
        String fn=f;
        int a=f.indexOf("->"), b=(a>=0)?f.indexOf(':',a+1):-1;
        if(a>=0 && b>a) fn=f.substring(a+2,b);
        if("pathList".equals(fn)) return vm.resolveClass("dalvik/system/DexPathList").newObject(null);
        if("dexElements".equals(fn)){
            DvmClass elem=vm.resolveClass("dalvik/system/DexPathList$Element");
            return new ArrayObject(new DvmObject<?>[]{ elem.newObject(null) });
        }
        if("dexFile".equals(fn)) return vm.resolveClass("dalvik/system/DexFile").newObject(null);
        if("name".equals(fn) || "mFileName".equals(fn)) return new StringObject(vm, "/data/app/com.hottagames.yh.laohu/base.apk");
        return null;
    }

    @Override public int getIntField(BaseVM vm, DvmObject<?> obj, String f){ log("getIntField "+obj.getObjectType()+"."+f); return 0; }

    @Override public DvmObject<?> newObject(BaseVM vm, DvmClass clazz, String m, VarArg va){ log("newObject "+clazz.getClassName()+"."+m+"("+va+")"); return clazz.newObject(null); }

    // DvmMethod 变体(未覆盖时 AbstractJni 默认抛 UnsupportedOperationException)
    @Override public int callIntMethod(BaseVM vm, DvmObject<?> obj, DvmMethod dm, VarArg va){ return callIntMethod(vm,obj,dm.getMethodName(),va); }
    @Override public long callLongMethod(BaseVM vm, DvmObject<?> obj, DvmMethod dm, VarArg va){ log("callLong(m) "+obj.getObjectType()+"."+dm.getMethodName()); return 0L; }
    @Override public boolean callBooleanMethod(BaseVM vm, DvmObject<?> obj, DvmMethod dm, VarArg va){ return false; }
    @Override public void callVoidMethod(BaseVM vm, DvmObject<?> obj, DvmMethod dm, VarArg va){ log("callVoid(m) "+obj.getObjectType()+"."+dm.getMethodName()); }
    @Override public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass c, DvmMethod dm, VarArg va){ return callStaticObjectMethod(vm,c,dm.getMethodName(),va); }
    @Override public int callStaticIntMethod(BaseVM vm, DvmClass c, DvmMethod dm, VarArg va){ return callStaticIntMethod(vm,c,dm.getMethodName(),va); }

    // V(VaList) 变体
    @Override public long callLongMethodV(BaseVM vm, DvmObject<?> obj, DvmMethod dm, VaList va){ long v=0; try{ if(obj instanceof com.github.unidbg.linux.android.dvm.wrapper.DvmLong) v=((com.github.unidbg.linux.android.dvm.wrapper.DvmLong)obj).getValue(); }catch(Throwable t){} return v; }
    @Override public int callIntMethodV(BaseVM vm, DvmObject<?> obj, DvmMethod dm, VaList va){ int v=0; try{ if(obj instanceof com.github.unidbg.linux.android.dvm.wrapper.DvmInteger) v=((com.github.unidbg.linux.android.dvm.wrapper.DvmInteger)obj).getValue(); }catch(Throwable t){} return v; }
    @Override public void callVoidMethodV(BaseVM vm, DvmObject<?> obj, DvmMethod dm, VaList va){ log("callVoidV "+obj.getObjectType()+"."+dm.getMethodName()); }
    @Override public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> obj, DvmMethod dm, VaList va){ return false; }
    @Override public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> obj, DvmMethod dm, VaList va){ return callObjectMethod(vm, obj, dm != null ? dm.getMethodName() : "?", va); }
    @Override public long callLongMethodV(BaseVM vm, DvmObject<?> obj, String m, VaList va){ long v=0; try{ if(obj instanceof com.github.unidbg.linux.android.dvm.wrapper.DvmLong) v=((com.github.unidbg.linux.android.dvm.wrapper.DvmLong)obj).getValue(); }catch(Throwable t){} return v; }
    @Override public int callIntMethodV(BaseVM vm, DvmObject<?> obj, String m, VaList va){ int v=0; try{ if(obj instanceof com.github.unidbg.linux.android.dvm.wrapper.DvmInteger) v=((com.github.unidbg.linux.android.dvm.wrapper.DvmInteger)obj).getValue(); }catch(Throwable t){} return v; }
    @Override public void callVoidMethodV(BaseVM vm, DvmObject<?> obj, String m, VaList va){ log("callVoidV "+obj.getObjectType()+"."+m); }
}
