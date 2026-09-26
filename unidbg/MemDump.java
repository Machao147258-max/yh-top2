import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.memory.MemoryMap;
import java.io.File;
import java.io.PrintWriter;
import java.util.*;

/** 运行 JNI_OnLoad + rL(独立线程跑，崩进调试器/挂住都无妨)，主线程 dump 运行时内存字符串。 */
public class MemDump {
    public static void main(String[] args) throws Exception {
        String APK="C:/Users/20751/Desktop/异环/apk/yh_gw_20260702.apk";
        String SO ="C:/Users/20751/Desktop/异环/unpacked/so/libsecsdk.so";
        final AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.hottagames.yh.laohu").build();
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        final VM vm = emulator.createDalvikVM(new File(APK));
        vm.setVerbose(false);
        vm.setJni(new MyJni());
        DalvikModule dm = vm.loadLibrary(new File(SO), false);
        Module m = dm.getModule();
        System.out.println("[*] base=0x"+Long.toHexString(m.base));
        vm.callJNI_OnLoad(emulator, m);
        System.out.println("[*] JNI_OnLoad done");

        Thread worker = new Thread(new Runnable(){ public void run(){
            DvmClass Utils = vm.resolveClass("com/netease/nis/sdkwrapper/Utils");
            Object[][] tries = { {"cmd",0,0L}, {"getInfo",1,1L}, {"/system/bin/su",0,0L}, {"magisk",0,0L} };
            for(Object[] t : tries){
                try{
                    DvmObject<?>[] objs = new DvmObject<?>[t.length];
                    for(int k=0;k<t.length;k++){
                        Object o=t[k];
                        if(o instanceof Integer) objs[k]=com.github.unidbg.linux.android.dvm.wrapper.DvmInteger.valueOf(vm,(Integer)o);
                        else if(o instanceof Long) objs[k]=com.github.unidbg.linux.android.dvm.wrapper.DvmLong.valueOf(vm,(Long)o);
                        else objs[k]=new StringObject(vm,String.valueOf(o));
                    }
                    Utils.callStaticJniMethodObject(emulator,"rL([Ljava/lang/Object;)Ljava/lang/Object;", vm.addLocalObject(new ArrayObject(objs)));
                }catch(Throwable e){}
            }
        }});
        worker.setDaemon(true);
        worker.start();
        Thread.sleep(4000);

        System.out.println("[*] dumping memory strings...");
        Set<String> strs = new LinkedHashSet<>();
        long total=0, cap=512L*1024*1024, maps=0, okmaps=0;
        try{
          Collection<MemoryMap> mmaps = emulator.getMemory().getMemoryMap();
          System.out.println("[*] maps="+mmaps.size());
          for(MemoryMap mm : mmaps){
            maps++;
            if(mm.size<=0) continue;
            long base=mm.base, size=Math.min(mm.size,cap), got=0;
            long chunk=256*1024;
            for(long off=0; off<size && total<cap; off+=chunk){
                long rd=Math.min(chunk,size-off);
                try{ byte[] buf=emulator.getBackend().mem_read(base+off, rd); total+=buf.length; got+=buf.length; scan(buf,strs); }catch(Throwable e){ break; }
            }
            if(got>0){ okmaps++; System.out.println("  map 0x"+Long.toHexString(base)+" size=0x"+Long.toHexString(mm.size)+" prot="+mm.prot+" read="+got); }
          }
        }catch(Throwable e){ System.out.println("scan err "+e); }
        System.out.println("[*] maps="+maps+" ok="+okmaps+" read="+total+" bytes, strings="+strs.size());
        try(PrintWriter pw=new PrintWriter("C:/Users/20751/Desktop/异环/unidbg/secsdk_memdump_strings.txt","UTF-8")){
            for(String s: strs) pw.println(s);
        }
        for(String s: strs){ if(s.length()>=6 && (s.contains("netease")||s.contains("yidun")||s.contains("vmp")||s.contains("VMP")||s.contains("ClassLoader")||s.contains("loadClass")||s.contains("/dex")||s.contains(".dex")||s.contains("Utils")||s.contains("risk")||s.contains("magisk")||s.contains("hook"))) System.out.println("  HIT: "+s); }
        System.out.println("[*] done");
        System.exit(0);
    }
    static void scan(byte[] b, Set<String> out){
        int n=b.length, i=0; StringBuilder sb=new StringBuilder();
        while(i<n){ int c=b[i]&0xff; if(c>=0x20 && c<0x7f){ sb.append((char)c); } else { if(sb.length()>=6) out.add(sb.toString()); sb.setLength(0);} i++; }
        if(sb.length()>=6) out.add(sb.toString());
    }
}
