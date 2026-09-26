"""探测 libmxcore_javasupport.so 在 unidbg 能否加载"""
import sys, os
sys.path.insert(0, r"C:\Users\20751\Desktop\异环\scripts")

# 直接写 Java 太麻烦，先用 idat 看能不能调通
# 改造 Demo.java 加个探测模式

java_code = '''
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
        vm.setVerbose(true);  // 开 verbose，看 JNI 回调
        vm.setJni(new MyJni());

        DalvikModule dm = vm.loadLibrary(
            new File("C:/Users/20751/Desktop/异环/unpacked/so/libmxcore_javasupport.so"), false);
        Module module = dm.getModule();
        System.out.println("[*] base = 0x" + Long.toHexString(module.base));

        vm.callJNI_OnLoad(emulator, module);
        System.out.println("[*] JNI_OnLoad done");

        // 尝试 resolve 一个类看看
        try {
            DvmClass Native = vm.resolveClass("com/sdk/mxsdk/im/core/Native");
            System.out.println("[+] resolveClass Native 成功");
        } catch (Exception e) {
            System.out.println("[!] resolveClass 失败: " + e.getMessage());
        }

        System.out.println("[*] 探测结束，so 已加载");
        emulator.close();
    }
}
'''

with open(r"C:\Users\20751\Desktop\异环\unidbg\ProbeMxcoreJava.java", "w", encoding="utf-8") as f:
    f.write(java_code)

print("[+] ProbeMxcoreJava.java 已写入")
print("[*] 编译: javac -cp ... ProbeMxcoreJava.java")
print("[*] 运行: java -cp ... ProbeMxcoreJava")