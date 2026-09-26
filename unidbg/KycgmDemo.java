import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.hook.hookzz.*;
import com.github.unidbg.pointer.UnidbgPointer;
import java.io.File;
import java.nio.charset.StandardCharsets;

/**
 * 异环 libkycgm.so unidbg 模拟
 * 
 * 目标: hook sm4CbcEncrypt 抄 key/iv/data
 * 地址: sm4CbcEncrypt @ 0x4ca8
 */
public class KycgmDemo {

    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    public KycgmDemo() {
        // 1. 造模拟器
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.hottagames.yh.laohu")
                .build();

        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        // 2. 建 Dalvik VM
        vm = emulator.createDalvikVM();
        vm.setVerbose(true);
        vm.setJni(new KycgmJni());

        // 3. 加载 so（先不跑 JNI_OnLoad）
        DalvikModule dm = vm.loadLibrary(
            new File("C:\\Users\\20751\\Desktop\\异环\\unpacked\\so\\libkycgm.so"), 
            false
        );
        module = dm.getModule();
        System.out.println("[*] libkycgm base = 0x" + Long.toHexString(module.base));
    }

    public void callSm4Encrypt() throws Exception {
        // 调 sm4CbcEncrypt(key, iv, data)
        byte[] key = hexStringToByteArray("0123456789ABCDEFFEDCBA9876543210");
        byte[] iv  = hexStringToByteArray("00000000000000000000000000000000");
        byte[] data = "Hello, Yihuan! 异环测试".getBytes(StandardCharsets.UTF_8);

        System.out.println("[*] key(" + key.length + "B) = " + bytesToHex(key));
        System.out.println("[*] iv(" + iv.length + "B) = " + bytesToHex(iv));
        System.out.println("[*] data(" + data.length + "B) = " + bytesToHex(data));

        // byte[] → jbyteArray
        int keyObj = vm.addLocalObject(new ByteArray(vm, key));
        int ivObj = vm.addLocalObject(new ByteArray(vm, iv));
        int dataObj = vm.addLocalObject(new ByteArray(vm, data));

        // call JNI
        Number r = module.callFunction(emulator, 
            "Java_com_kycgm_GmCipher_sm4CbcEncrypt",
            vm.getJNIEnv(),  // JNIEnv*
            0,              // jclass (static)
            keyObj, ivObj, dataObj
        );

        // 返回值是 jbyteArray
        if (r != null) {
            DvmObject<?> result = vm.getObject(r.intValue());
            if (result != null && result.getValue() instanceof byte[]) {
                byte[] ciphertext = (byte[]) result.getValue();
                System.out.println("[+] sm4CbcEncrypt 密文(" + ciphertext.length + "B) = " 
                    + bytesToHex(ciphertext));
            } else {
                System.out.println("[!] 返回非 byte[]: " + result);
            }
        } else {
            System.out.println("[!] 返回 null");
        }
    }

    public void callSm4Decrypt(byte[] key, byte[] iv, byte[] ciphertext) throws Exception {
        int keyObj = vm.addLocalObject(new ByteArray(vm, key));
        int ivObj = vm.addLocalObject(new ByteArray(vm, iv));
        int dataObj = vm.addLocalObject(new ByteArray(vm, ciphertext));

        Number r = module.callFunction(emulator,
            "Java_com_kycgm_GmCipher_sm4CbcDecrypt",
            vm.getJNIEnv(), 0,
            keyObj, ivObj, dataObj
        );

        if (r != null) {
            DvmObject<?> result = vm.getObject(r.intValue());
            if (result != null && result.getValue() instanceof byte[]) {
                byte[] plain = (byte[]) result.getValue();
                String text = new String(plain, StandardCharsets.UTF_8);
                System.out.println("[+] sm4CbcDecrypt 明文: " + text);
                System.out.println("[+] 闭环验证 " + (text.contains("异环") ? "✅" : "❌"));
            }
        }
    }

    public void hookSm4Encrypt() {
        long hookAddr = module.base + 0x4ca8;
        System.out.println("[*] hook sm4CbcEncrypt @ 0x" + Long.toHexString(hookAddr));

        HookZz hookZz = HookZz.getInstance(emulator);
        hookZz.replace(hookAddr, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator<?> emu, HookContext ctx, long addr) {
                System.out.println("\n=== sm4CbcEncrypt 被调 ===");
                // ARM64 参数: x0=JNIEnv, x1=jclass, x2=key, x3=iv, x4=data
                UnidbgPointer keyPtr = ctx.getPointerArg(2);
                UnidbgPointer ivPtr = ctx.getPointerArg(3);
                UnidbgPointer dataPtr = ctx.getPointerArg(4);

                if (keyPtr != null) {
                    byte[] key = keyPtr.getByteArray(0, 16);
                    System.out.println("  key = " + bytesToHex(key));
                }
                if (ivPtr != null) {
                    byte[] iv = ivPtr.getByteArray(0, 16);
                    System.out.println("  iv  = " + bytesToHex(iv));
                }
                return HookStatus.LR(emu, 0);
            }
        });
    }

    public void close() {
        emulator.close();
    }

    // ──── 工具函数 ────
    static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X", b));
        return sb.toString();
    }

    static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i + 1), 16));
        return data;
    }

    // ──── JNI 回调 ────
    static class KycgmJni extends AbstractJni {
        // libkycgm.so 的 JNI 回调很轻量，最小实现
    }

    // ──── 主入口 ────
    public static void main(String[] args) throws Exception {
        KycgmDemo demo = new KycgmDemo();

        System.out.println("\n=== 1. 原始加密 ===");
        demo.callSm4Encrypt();

        System.out.println("\n=== 2. 安装 hook ===");
        demo.hookSm4Encrypt();

        System.out.println("\n=== 3. 再调一次（看 hook 输出）===");
        demo.callSm4Encrypt();

        demo.close();
        System.out.println("\n[done]");
    }
}