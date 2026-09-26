import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;
import java.io.File;

public class JavasupportProbe {
    public static void main(String[] args) throws Exception {
        System.out.println("[*] 单独加载 libmxcore_javasupport.so");

        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.hottagames.yh.laohu").build();
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));

        VM vm = emulator.createDalvikVM();
        vm.setVerbose(false);
        vm.setJni(new MyJni());

        System.out.println("[*] 加载 SO...");
        DalvikModule dm = vm.loadLibrary(
            new File("C:/Users/20751/Desktop/异环/unpacked/so/libmxcore_javasupport.so"), false);
        Module m = dm.getModule();
        System.out.println("[+] base = 0x" + Long.toHexString(m.base));

        System.out.println("[*] JNI_OnLoad...");
        try {
            vm.callJNI_OnLoad(emulator, dm.getModule());
            System.out.println("[+] JNI_OnLoad OK");
        } catch (Exception e) {
            System.out.println("[!] JNI_OnLoad: " + e.getClass().getSimpleName() + " - " + e.getMessage());
        }

        try {
            DvmClass Native = vm.resolveClass("com/sdk/mxsdk/im/core/Native");
            System.out.println("[+] resolveClass OK");
        } catch (Exception e) {
            System.out.println("[!] resolveClass: " + e.getMessage());
        }

        System.out.println("[*] done");
        emulator.close();
    }
}