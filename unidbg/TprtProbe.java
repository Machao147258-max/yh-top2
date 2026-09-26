import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import java.io.*;

/** libtprt(腾讯ACE) 探针: hook tp_syscall_imp + libc, 跑 JNI_OnLoad + native 方法。 */
public class TprtProbe {
    static AndroidEmulator emulator;
    static int nSc=0, nOpen=0;
    public static void main(String[] args) throws Exception {
        String APK="C:/Users/20751/Desktop/异环/apk/yh_gw_20260702.apk";
        String SO ="C:/Users/20751/Desktop/异环/unpacked/so/libtprt.so";
        if(!new File(SO).exists()) SO="D:/qwork/libtprt.so";
        emulator = AndroidEmulatorBuilder.for64Bit().setProcessName("com.hottagames.yh.laohu").build();
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        final VM vm = emulator.createDalvikVM(new File(APK));
        vm.setVerbose(false);
        vm.setJni(new MyJni());
        DalvikModule dm = vm.loadLibrary(new File(SO), true);
        final Module m = dm.getModule();
        final long base=m.base;
        System.out.println("[*] base=0x"+Long.toHexString(base)+" size=0x"+Long.toHexString(m.size));
        // hook 自有 syscall 引擎
        hook(base+0x146be0, "tp_syscall_imp", true);
        hook(base+0x2641c, "JNI_OnLoad", false);
        hook(base+0x2603c, "ev-svc", false);
        hook(base+0x25ae0, "initialize", false);
        hook(base+0x136d7c, "ioctl", false);
        // hook libc 文件
        try{
            for(final String fn : new String[]{"open","openat","fopen","__open_2"}){
                Module libc=emulator.getMemory().findModule("libc.so");
                if(libc==null) break;
                com.github.unidbg.Symbol sy=libc.findSymbolByName(fn,false);
                if(sy!=null && !sy.isUndef()){
                    final String f2=fn;
                    emulator.getBackend().hook_add_new(new CodeHook(){
                        public void hook(Backend b,long a,int sz,Object u){
                            if(nOpen++>200) return;
                            long p0=emulator.getContext().getLongArg(0), p1=emulator.getContext().getLongArg(1);
                            String s; try{ s=readCStr(p1)+" | "+readCStr(p0);}catch(Throwable t){ s="?"; }
                            System.out.println("[LIBC:"+f2+"] "+s);
                        }
                        public void onAttach(UnHook h){} public void detach(){}
                    }, sy.getAddress(), sy.getAddress(), null);
                }
            }
        }catch(Throwable t){ System.out.println("libchook err "+t); }
        System.out.println("=== JNI_OnLoad ===");
        vm.callJNI_OnLoad(emulator, m);
        System.out.println("=== 取串 sub_111740(id) (off_163750[id%100]()) ===");
        for(long id=0; id<=2000; id++){
            try{
                Number rr = m.callFunction(emulator, 0x111740, id);
                long p = rr.longValue();
                String str=readCStr(p);
                if(str.length()>0) System.out.println("  ["+id+"] -> '"+str+"'");
            }catch(Throwable e){}
        }        // 调 native 方法
        try{
            DvmClass c = vm.resolveClass("com/ace/gshell/AceApplication");
            System.out.println("=== gp7ioctl(\"stop\") ===");
            c.callStaticJniMethod(emulator, "gp7ioctl(Ljava/lang/String;)V", vm.addLocalObject(new StringObject(vm,"stop")));
            System.out.println("=== ioctl(1,\"...\") ===");
            c.callStaticJniMethodInt(emulator, "ioctl(ILjava/lang/String;)I", 1, vm.addLocalObject(new StringObject(vm,"1")));
        }catch(Throwable e){ System.out.println("call err "+e); }
        System.out.println("\n[*] tp_syscall_imp hits="+nSc+" libc-open hits="+nOpen);
        emulator.close();
    }
    static void hook(long addr, final String tag, final boolean isSc){
        emulator.getBackend().hook_add_new(new CodeHook(){
            public void hook(Backend b, long a, int s, Object u){
                if(nSc++>300) return;
                try{
                    long nr=emulator.getContext().getLongArg(0);
                    StringBuilder sb=new StringBuilder("["+tag+"] nr="+nr);
                    long p2=emulator.getContext().getLongArg(2);
                    String path=readCStr(p2);
                    if(path.length()>=2) sb.append(" path='"+path+"'");
                    System.out.println(sb.toString());
                }catch(Throwable t){}
            }
            public void onAttach(UnHook h){} public void detach(){}
        }, addr, addr, null);
    }
    static String readCStr(long addr){ StringBuilder s=new StringBuilder(); try{ for(int i=0;i<160;i++){ byte[] b=emulator.getBackend().mem_read(addr+i,1); if(b[0]==0) break; char c=(char)(b[0]&0xff); if(c<0x20||c>0x7e) break; s.append(c);} }catch(Throwable t){} return s.toString(); }
}
