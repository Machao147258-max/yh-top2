import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.MemoryMap;
import java.io.File;
import java.io.FileOutputStream;
import java.util.*;

/** 把 libsecsdk 运行时映射段原样 dump 出来（用于和磁盘 SO 对比，找出解密段）。 */
public class SegDump {
    public static void main(String[] args) throws Exception {
        String APK="C:/Users/20751/Desktop/异环/apk/yh_gw_20260702.apk";
        String SO ="C:/Users/20751/Desktop/异环/unpacked/so/libsecsdk.so";
        final AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.hottagames.yh.laohu").build();
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        VM vm = emulator.createDalvikVM(new File(APK));
        vm.setVerbose(false); vm.setJni(new MyJni());
        DalvikModule dm = vm.loadLibrary(new File(SO), false);
        Module m = dm.getModule();
        long base=m.base;
        System.out.println("[*] base=0x"+Long.toHexString(base)+" size=0x"+Long.toHexString(m.size));
        vm.callJNI_OnLoad(emulator, m);
        // 短驱动一下 rL
        try{ vm.resolveClass("com/netease/nis/sdkwrapper/Utils"); }catch(Throwable e){}

        FileOutputStream fos=new FileOutputStream("C:/Users/20751/Desktop/异环/unidbg/secsdk_seg.bin");
        long end=base+m.size+0x20000;
        long chunk=256*1024;
        long total=0;
        for(long off=0; off<end-base; off+=chunk){
            long rd=Math.min(chunk,end-base-off);
            try{ byte[] buf=emulator.getBackend().mem_read(base+off, rd); fos.write(buf); total+=buf.length; }
            catch(Throwable e){ byte[] z=new byte[(int)rd]; fos.write(z); total+=rd; }
        }
        fos.close();
        System.out.println("[*] 写出 "+total+" 字节 -> secsdk_seg.bin (镜像基址0x"+Long.toHexString(base)+")");
        emulator.close();
        System.exit(0);
    }
}
