import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;
import java.io.File;

public class CombinedProbe {
    public static void main(String[] args) throws Exception {
        System.out.println("[*] 联合加载: libmxcore + libmxcore_javasupport");

        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.hottagames.yh.laohu").build();
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));

        VM vm = emulator.createDalvikVM(new File("C:/Users/20751/Desktop/异环/apk/yh_gw_20260702.apk"));
        vm.setVerbose(false);
        vm.setJni(new MyJni());

        // 1. 先加载引擎
        System.out.println("\n=== 加载 libmxcore.so ===");
        DalvikModule dmCore = vm.loadLibrary(
            new File("C:/Users/20751/Desktop/异环/unpacked/so/libmxcore.so"), false);
        Module mc = dmCore.getModule();
        System.out.println("[*] libmxcore base = 0x" + Long.toHexString(mc.base));

        // 2. 加载 JNI 桥
        System.out.println("\n=== 加载 libmxcore_javasupport.so ===");
        DalvikModule dmJava = vm.loadLibrary(
            new File("C:/Users/20751/Desktop/异环/unpacked/so/libmxcore_javasupport.so"), false);
        Module mj = dmJava.getModule();
        System.out.println("[*] libmxcore_javasupport base = 0x" + Long.toHexString(mj.base));

        // 3. JNI_OnLoad
        System.out.println("\n=== JNI_OnLoad ===");
        vm.callJNI_OnLoad(emulator, dmJava.getModule());
        System.out.println("[+] JNI_OnLoad done");

        // 4. 尝试 resolve 类
        try {
            DvmClass Native = vm.resolveClass("com/sdk/mxsdk/im/core/Native");
            System.out.println("[+] resolveClass Native OK");
            
            // 调 pwim_version (最简单，无参数，返回字符串)
            Number r = mj.callFunction(vm.getEmulator(),
                "Java_com_sdk_mxsdk_im_core_Native_pwim_1version",
                vm.getJNIEnv(), vm.addLocalObject(Native));
            if (r != null) {
                DvmObject<?> ver = vm.getObject(r.intValue());
                System.out.println("[+] pwim_version = " + (ver != null ? ver.getValue() : "null"));
            }
        } catch (Exception e) {
            System.out.println("[!] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        System.out.println("\n[*] 结束");
        emulator.close();
    }
}