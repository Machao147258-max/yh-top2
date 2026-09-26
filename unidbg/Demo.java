import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;
import java.io.File;
import java.nio.charset.StandardCharsets;

public class Demo {

    static Object callJni(VM vm, Module m, String sym, Object... args) {
        Number r = m.callFunction(vm.getEmulator(), sym, args);
        if (r == null) return null;
        DvmObject<?> o = vm.getObject(r.intValue());
        return o == null ? null : o.getValue();
    }

    static Object sm4Encrypt(VM vm, Module m, DvmClass cls, byte[] key, byte[] iv, byte[] data) {
        return callJni(vm, m,
            "Java_com_kycgm_GmCipher_sm4CbcEncrypt",
            vm.getJNIEnv(), vm.addLocalObject(cls),
            vm.addLocalObject(new ByteArray(vm, key)),
            vm.addLocalObject(new ByteArray(vm, iv)),
            vm.addLocalObject(new ByteArray(vm, data)));
    }

    static Object sm4Decrypt(VM vm, Module m, DvmClass cls, byte[] key, byte[] iv, byte[] data) {
        return callJni(vm, m,
            "Java_com_kycgm_GmCipher_sm4CbcDecrypt",
            vm.getJNIEnv(), vm.addLocalObject(cls),
            vm.addLocalObject(new ByteArray(vm, key)),
            vm.addLocalObject(new ByteArray(vm, iv)),
            vm.addLocalObject(new ByteArray(vm, data)));
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    static boolean bytesEqual(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        for (int i = 0; i < a.length; i++)
            if (a[i] != b[i]) return false;
        return true;
    }

    // ===== libkycgm.so SM4 密钥验证 =====
    static void testKycgm(VM vm, Module module) throws Exception {
        DvmClass GmCipher = vm.resolveClass("com/kycgm/GmCipher");
        byte[] plain = "hello_yihuan_test".getBytes(StandardCharsets.UTF_8);

        System.out.println("\n========== libkycgm.so SM4 测试 ==========");

        // 测试1: 全零 key + IV
        byte[] k1 = new byte[16], iv1 = new byte[16];
        byte[] c1 = (byte[]) sm4Encrypt(vm, module, GmCipher, k1, iv1, plain);
        System.out.println("Test1 key全零+IV全零: " + hex(c1));

        // 测试2: 全零 key + 非零IV
        byte[] k2 = new byte[16];
        byte[] iv2 = "0102030405060708".getBytes(StandardCharsets.UTF_8);
        byte[] c2 = (byte[]) sm4Encrypt(vm, module, GmCipher, k2, iv2, plain);
        System.out.println("Test2 key全零+IV非零: " + hex(c2));

        // 测试3: 非零 key + 全零IV
        byte[] k3 = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        byte[] iv3 = new byte[16];
        byte[] c3 = (byte[]) sm4Encrypt(vm, module, GmCipher, k3, iv3, plain);
        System.out.println("Test3 key非零+IV全零: " + hex(c3));

        // 结论
        System.out.println("\n结论:");
        System.out.println("  改IV " + (bytesEqual(c1, c2) ? "密文不变 ❌ IV被忽略" : "密文改变 ✅ IV生效"));
        System.out.println("  改key " + (bytesEqual(c1, c3) ? "密文不变 ❌ key硬编码" : "密文改变 ✅ key参数生效"));

        // 闭环解密
        byte[] dec = (byte[]) sm4Decrypt(vm, module, GmCipher, k3, iv3, c3);
        String decStr = new String(dec, StandardCharsets.UTF_8);
        System.out.println("  解密验证: " + decStr + (decStr.contains("yihuan") ? " ✅" : " ❌"));
    }

    // ===== libmxcore_javasupport.so IM 扫描 =====
    static void scanMxcoreJava(VM vm, Module module) throws Exception {
        System.out.println("\n========== libmxcore_javasupport.so ==========");
        System.out.println("[*] module base = 0x" + Long.toHexString(module.base));
        System.out.println("[*] 140 JNI exports available, can call pwim_init etc.");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("[*] 异环 SO unidbg 综合测试");

        // ===== 1. libkycgm.so =====
        System.out.println("\n--- 加载 libkycgm.so ---");
        AndroidEmulator em1 = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.hottagames.yh.laohu").build();
        em1.getMemory().setLibraryResolver(new AndroidResolver(23));
        VM vm1 = em1.createDalvikVM(new File("C:/Users/20751/Desktop/异环/apk/yh_gw_20260702.apk"));
        vm1.setVerbose(false);
        vm1.setJni(new MyJni());
        DalvikModule dm1 = vm1.loadLibrary(
            new File("C:/Users/20751/Desktop/异环/unpacked/so/libkycgm.so"), false);
        vm1.callJNI_OnLoad(em1, dm1.getModule());
        testKycgm(vm1, dm1.getModule());
        em1.close();

        // ===== 2. libmxcore_javasupport.so =====
        System.out.println("\n--- 加载 libmxcore_javasupport.so ---");
        AndroidEmulator em2 = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.hottagames.yh.laohu").build();
        em2.getMemory().setLibraryResolver(new AndroidResolver(23));
        VM vm2 = em2.createDalvikVM(new File("C:/Users/20751/Desktop/异环/apk/yh_gw_20260702.apk"));
        vm2.setVerbose(false);
        vm2.setJni(new MyJni());
        DalvikModule dm2 = vm2.loadLibrary(
            new File("C:/Users/20751/Desktop/异环/unpacked/so/libmxcore_javasupport.so"), false);
        vm2.callJNI_OnLoad(em2, dm2.getModule());
        scanMxcoreJava(vm2, dm2.getModule());
        em2.close();

        System.out.println("\n[done]");
    }
}