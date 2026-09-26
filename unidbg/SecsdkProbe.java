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

/** 探针: hook 解析器 0xc1c8 / 字节码写入 0xc2fc / 触发 0xbe5c / 解释器 0x307b8, 用正确 rL 驱动。 */
public class SecsdkProbe {
    static AndroidEmulator emulator;
    static FileOutputStream cap;
    static int nParser=0, nWrite=0, nVt3=0, nDisp=0;
    public static void main(String[] args) throws Exception {
        String APK="C:/Users/20751/Desktop/异环/apk/yh_gw_20260702.apk";
        String SO ="C:/Users/20751/Desktop/异环/unpacked/so/libsecsdk.so";
        emulator = AndroidEmulatorBuilder.for64Bit().setProcessName("com.hottagames.yh.laohu").build();
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        final VM vm = emulator.createDalvikVM(new File(APK));
        vm.setVerbose(true);
        vm.setJni(new MyJni());
        DalvikModule dm = vm.loadLibrary(new File(SO), false);
        final Module m = dm.getModule();
        final long base=m.base;
        System.out.println("[*] base=0x"+Long.toHexString(base));
        cap=new FileOutputStream("C:/Users/20751/Desktop/异环/unidbg/parser_capture.bin");
        addHook(base+0xc1c8, "PARSER", new int[]{0,1,2});
        addHook(base+0xc2fc, "WRITE",  new int[]{25,26});
        addHook(base+0xbe5c, "VT3",    new int[]{0,1,2});
        addHook(base+0xbdb0, "VT30",   new int[]{0,1});
        addHook(base+0xbea0, "CBZ20",  new int[]{20});
        addHook(base+0xbf20, "CALLP",  new int[]{0,1,2});
        addHook(base+0x1f500,"OPEN",   new int[]{0,1,2,3});
        addHook(base+0x307b8,"DISP",   new int[]{});
        // libc 文件打开探针
        try{
            Module libc=emulator.getMemory().findModule("libc.so");
            System.out.println("[*] libc="+(libc==null?"null":("0x"+Long.toHexString(libc.base))));
            if(libc!=null){
                for(final String fn : new String[]{"open","openat","fopen","__open_2"}){
                    try{
                        com.github.unidbg.Symbol sy=libc.findSymbolByName(fn,false);
                        if(sy!=null && !sy.isUndef()){
                            emulator.getBackend().hook_add_new(new CodeHook(){
                                public void hook(Backend b,long a,int sz,Object u){
                                    long p0=emulator.getContext().getLongArg(0), p1=emulator.getContext().getLongArg(1);
                                    try{ System.out.println("[LIBC:"+fn+"] x0="+readCStr(p0)+" | x1="+readCStr(p1)); }catch(Throwable t){}
                                }
                                public void onAttach(UnHook h){} public void detach(){}
                            }, sy.getAddress(), sy.getAddress(), null);
                            System.out.println("    hook libc "+fn+" @0x"+Long.toHexString(sy.getAddress()));
                        }
                    }catch(Throwable t){}
                }
            }
        }catch(Throwable t){ System.out.println("libchook err "+t); }

        System.out.println("=== JNI_OnLoad ===");
        vm.callJNI_OnLoad(emulator, m);
        try{ vm.resolveClass("com/netease/nis/sdkwrapper/Utils"); }catch(Throwable e){}
        try{
            DvmClass Utils = vm.resolveClass("com/netease/nis/sdkwrapper/Utils");
            DvmObject<?>[] objs = new DvmObject<?>[]{
                new StringObject(vm,""),
                com.github.unidbg.linux.android.dvm.wrapper.DvmInteger.valueOf(vm,14),
                com.github.unidbg.linux.android.dvm.wrapper.DvmLong.valueOf(vm,1606976968486L)};
            Utils.callStaticJniMethodObject(emulator,"rL([Ljava/lang/Object;)Ljava/lang/Object;", vm.addLocalObject(new ArrayObject(objs)));
        }catch(Throwable e){ System.out.println("rL 异常 "+e); }
        System.out.println("\n[*] PARSER="+nParser+" WRITE="+nWrite+" VT3="+nVt3+" DISP="+nDisp);
        cap.close();
        emulator.close();
    }
    static void addHook(long addr, final String tag, final int[] regs){
        emulator.getBackend().hook_add_new(new CodeHook(){
            public void hook(Backend b, long a, int s, Object u){
                try{
                    if(tag.equals("PARSER")){ if(nParser++>500) return; }
                    else if(tag.equals("WRITE")){ if(nWrite++>500) return; }
                    else if(tag.equals("VT3")){ if(nVt3++>50) return; }
                    else { if(nDisp++>300) return; }
                    StringBuilder sb=new StringBuilder("["+tag+"] ");
                    for(int r: regs) sb.append("x"+r+"=0x"+Long.toHexString(emulator.getContext().getLongArg(r))+" ");
                    if(tag.equals("PARSER") && regs.length==3){
                        long buf=emulator.getContext().getLongArg(1), len=emulator.getContext().getLongArg(2)&0xffffffffL;
                        if(len>0 && len<0x20000){ byte[] bb=emulator.getBackend().mem_read(buf,len); cap.write(bb); cap.flush(); sb.append(" bufDump="+len); }
                    }
                    if(tag.equals("WRITE")){
                        long bc=emulator.getContext().getLongArg(26);
                        try{ byte[] bb=emulator.getBackend().mem_read(bc,48); sb.append(" bc="+hex(bb)); }catch(Throwable t){ sb.append(" bcread-fail"); }
                    }
                    if(tag.equals("CBZ20")){
                        long p=emulator.getContext().getLongArg(20);
                        try{ byte[] bb=emulator.getBackend().mem_read(p,96); sb.append(" obj="+hex(bb)); }catch(Throwable t){ sb.append(" readfail"); }
                        try{ byte[] q=emulator.getBackend().mem_read(p+0x30,8); long p2=0; for(int i=7;i>=0;i--)p2=(p2<<8)|(q[i]&0xff);
                             byte[] d=emulator.getBackend().mem_read(p2,64); sb.append(" +30->0x"+Long.toHexString(p2)+" data="+hex(d)); }catch(Throwable t){ sb.append(" deref-fail"); }
                    }
                    if(tag.equals("CALLP")){ sb.append(" !!!REACHED-PARSER-CALL"); }
                    if(tag.equals("OPEN")){ long p=emulator.getContext().getLongArg(0); sb.append(" path='"+readCStr(p)+"' x1=0x"+Long.toHexString(emulator.getContext().getLongArg(1))+" x2=0x"+Long.toHexString(emulator.getContext().getLongArg(2))); }
                    System.out.println(sb.toString());
                }catch(Throwable t){}
            }
            public void onAttach(UnHook h){}
            public void detach(){}
        }, addr, addr, null);
    }
    static String hex(byte[] b){ StringBuilder s=new StringBuilder(); for(byte x:b) s.append(String.format("%02x",x)); return s.toString(); }
    static String readCStr(long addr){ StringBuilder s=new StringBuilder(); try{ for(int i=0;i<200;i++){ byte[] b=emulator.getBackend().mem_read(addr+i,1); if(b[0]==0) break; char c=(char)(b[0]&0xff); if(c<0x20||c>0x7e) break; s.append(c);} }catch(Throwable t){} return s.toString(); }
}
