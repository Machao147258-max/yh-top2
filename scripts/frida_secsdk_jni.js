/*
 * frida_secsdk_jni.js —— 拦住 libsecsdk **对 Java 的一切调用**(JNIEnv 层)
 * 用法: frida -U -f com.hottagames.yh.laohu -l frida_secsdk_jni.js
 *
 * 思路("调用什么搞什么"): libsecsdk 的 VMP 通过 JNIEnv 函数表回调 Java
 *   (FindClass/GetMethodID/CallX/NewStringUTF/RegisterNatives/... 等)。
 *   钩这些表项, 只在【调用方=libsecsdk.so】时打印 → 完整还原它对 Java 的调用面。
 */
'use strict';
const TAG='[secsdk-jni]';
function L(){ console.log.apply(console, [TAG].concat([].slice.call(arguments))); }
function cstr(p){ try{return (p && !p.isNull())?p.readCString():'null';}catch(e){return '?';} }

Java.perform(function(){
  const psize=Process.pointerSize;
  let env, funcs;
  try{ env=Java.vm.getEnv(); funcs=env.readPointer(); }
  catch(e){ L('取 JNIEnv 失败', e); return; }
  L('JNIEnv='+env+' functions='+funcs);

  function inSecsdk(ra){ try{ const m=Process.findModuleByAddress(ra); return m && /libsecsdk/.test(m.name); }catch(e){ return false; } }
  function clsName(obj){ try{ return Java.cast(obj, Java.use('java.lang.Class')).getName(); }catch(e){ return '?'; } }
  function objCls(obj){ try{ return obj.$className || '?'; }catch(e){ return '?'; } }

  // 索引表(JNINativeInterface_)
  const IDX={
    FindClass:6, GetObjectClass:31, GetMethodID:33, GetFieldID:94,
    GetStaticMethodID:113, GetStaticFieldID:144, NewObject:28,
    CallObjectMethod:34, CallStaticObjectMethod:114, CallBooleanMethod:37,
    CallStaticBooleanMethod:117, CallIntMethod:49, CallStaticIntMethod:129,
    CallVoidMethod:61, CallStaticVoidMethod:141,
    NewStringUTF:167, GetStringUTFChars:169,
    GetObjectField:95, GetStaticObjectField:145,
    RegisterNatives:215, ExceptionCheck:228, ExceptionOccurred:15
  };
  function hook(idx, name, cb){
    const fp=funcs.add(idx*psize).readPointer();
    try{ Interceptor.attach(fp, { onEnter:function(a){ if(inSecsdk(this.returnAddress)) cb.call(this,a); } }); }
    catch(e){ L(name+' 挂钩失败',e); }
  }

  hook(IDX.FindClass, 'FindClass', function(a){ L('FindClass("'+cstr(a[1])+'")'); });
  hook(IDX.GetObjectClass, 'GetObjectClass', function(a){ L('GetObjectClass('+objCls(a[1])+')'); });
  hook(IDX.GetMethodID, 'GetMethodID', function(a){ L('GetMethodID('+clsName(a[1])+', "'+cstr(a[2])+'", "'+cstr(a[3])+'")'); });
  hook(IDX.GetStaticMethodID, 'GetStaticMethodID', function(a){ L('GetStaticMethodID('+clsName(a[1])+', "'+cstr(a[2])+'", "'+cstr(a[3])+'")'); });
  hook(IDX.GetFieldID, 'GetFieldID', function(a){ L('GetFieldID('+clsName(a[1])+', "'+cstr(a[2])+'", "'+cstr(a[3])+'")'); });
  hook(IDX.GetStaticFieldID, 'GetStaticFieldID', function(a){ L('GetStaticFieldID('+clsName(a[1])+', "'+cstr(a[2])+'", "'+cstr(a[3])+'")'); });
  hook(IDX.NewStringUTF, 'NewStringUTF', function(a){ L('NewStringUTF("'+cstr(a[1])+'")'); });
  hook(IDX.CallStaticObjectMethod, 'CallStaticObjectMethod', function(a){ L('CallStaticObjectMethod('+clsName(a[1])+', mid='+a[2]+')'); });
  hook(IDX.CallStaticVoidMethod, 'CallStaticVoidMethod', function(a){ L('CallStaticVoidMethod('+clsName(a[1])+', mid='+a[2]+')'); });
  hook(IDX.CallStaticIntMethod, 'CallStaticIntMethod', function(a){ L('CallStaticIntMethod('+clsName(a[1])+', mid='+a[2]+')'); });
  hook(IDX.CallStaticBooleanMethod, 'CallStaticBooleanMethod', function(a){ L('CallStaticBooleanMethod('+clsName(a[1])+', mid='+a[2]+')'); });
  hook(IDX.CallObjectMethod, 'CallObjectMethod', function(a){ L('CallObjectMethod('+objCls(a[1])+', mid='+a[2]+')'); });
  hook(IDX.NewObject, 'NewObject', function(a){ L('NewObject('+clsName(a[1])+', mid='+a[2]+')'); });
  hook(IDX.RegisterNatives, 'RegisterNatives', function(a){ L('RegisterNatives(cls='+a[1]+', methods='+a[2]+', n='+a[3].toInt32()+')'); });
  hook(IDX.GetStaticObjectField, 'GetStaticObjectField', function(a){ L('GetStaticObjectField('+clsName(a[0])+', fid='+a[2]+')'); });
  hook(IDX.ExceptionOccurred, 'ExceptionOccurred', function(a){ L('ExceptionOccurred()'); });

  L('=== frida_secsdk_jni.js 就绪 (libsecsdk 的 Java 调用面) ===');
});
