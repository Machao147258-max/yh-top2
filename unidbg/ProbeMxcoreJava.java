import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;
import java.io.File;

public class ProbeMxcoreJava {
    public static void main(String[] args) throws Exception {
        System.out.println("[*] 探测 libmxcore_javasupport.so");

        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.hottagames.yh.laohu").build();
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));

        VM vm = emulator.createDalvikVM(new File("C:/Users/20751/Desktop/异环/apk/yh_gw_20260702.apk"));
        vm.setVerbose(true);
        vm.setJni(new MyJni());

        DalvikModule dm = vm.loadLibrary(
            new File("C:/Users/20751/Desktop/异环/unpacked/so/libmxcore_javasupport.so"), false);
        Module module = dm.getModule();
        System.out.println("[*] base = 0x" + Long.toHexString(module.base));

        vm.callJNI_OnLoad(emulator, module);
        System.out.println("[*] JNI_OnLoad done");

        try {
            DvmClass Native = vm.resolveClass("com/sdk/mxsdk/im/core/Native");
            System.out.println("[+] resolveClass Native OK");
        } catch (Exception e) {
            System.out.println("[!] resolveClass: " + e.getMessage());
        }

        System.out.println("[*] 探测结束");
        emulator.close();
    }
}