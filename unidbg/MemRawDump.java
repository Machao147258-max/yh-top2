import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.memory.MemoryMap;
import java.io.*;
import java.util.*;

/** JNI_OnLoad(+可选 rL 触发) 后, 把全部内存 map 原样 dump -> secsdk_fullmem.bin + 索引 .idx。 */
public class MemRawDump {
    public static void main(String[] args) throws Exception {
        String APK="C:/Users/20751/Desktop/异环/apk/yh_gw_20260702.apk";
        String SO ="C:/Users/20751/Desktop/异环/unpacked/so/libsecsdk.so";
        final AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.hottagames.yh.laohu").build();
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        final VM vm = emulator.createDalvikVM(new File(APK));
        vm.setVerbose(false); vm.setJni(new MyJni());
        DalvikModule dm = vm.loadLibrary(new File(SO), false);
        final Module m = dm.getModule();
        System.out.println("[*] base=0x"+Long.toHexString(m.base));
        vm.callJNI_OnLoad(emulator, m);
        System.out.println("[*] JNI_OnLoad done");

        boolean doRL = args.length>0 && args[0].equals("rl");
        if(doRL){
            Thread worker = new Thread(new Runnable(){ public void run(){
                try{
                    DvmClass Utils = vm.resolveClass("com/netease/nis/sdkwrapper/Utils");
                    DvmObject<?>[] objs = new DvmObject<?>[]{
                        new StringObject(vm,""),
                        com.github.unidbg.linux.android.dvm.wrapper.DvmInteger.valueOf(vm,14),
                        com.github.unidbg.linux.android.dvm.wrapper.DvmLong.valueOf(vm,1606976968486L)};
                    Utils.callStaticJniMethodObject(emulator,"rL([Ljava/lang/Object;)Ljava/lang/Object;", vm.addLocalObject(new ArrayObject(objs)));
                }catch(Throwable e){ System.out.println("  rL 异常 "+e); }
            }});
            worker.setDaemon(true); worker.start();
            Thread.sleep(4000);
        }

        FileOutputStream fos=new FileOutputStream("C:/Users/20751/Desktop/异环/unidbg/secsdk_fullmem.bin");
        PrintWriter idx=new PrintWriter("C:/Users/20751/Desktop/异环/unidbg/secsdk_fullmem.idx","UTF-8");
        Collection<MemoryMap> mmaps = emulator.getMemory().getMemoryMap();
        long total=0, fileoff=0; int ok=0;
        long chunk=1024*1024;
        for(MemoryMap mm : mmaps){
            if(mm.size<=0) continue;
            idx.printf("0x%x 0x%x %s 0x%x%n", mm.base, mm.size, mm.prot, fileoff);
            long got=0;
            for(long off=0; off<mm.size; off+=chunk){
                long rd=Math.min(chunk,mm.size-off);
                try{ byte[] buf=emulator.getBackend().mem_read(mm.base+off, rd); fos.write(buf); total+=buf.length; got+=buf.length; }
                catch(Throwable e){ byte[] z=new byte[(int)rd]; fos.write(z); total+=z.length; got+=z.length; }
            }
            fileoff+=got; ok++;
        }
        fos.close(); idx.close();
        System.out.println("[*] maps="+mmaps.size()+" ok="+ok+" 写出 "+total+" -> secsdk_fullmem.bin");
        emulator.close(); System.exit(0);
    }
}
