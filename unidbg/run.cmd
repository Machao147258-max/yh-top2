@echo off
chcp 65001 >nul
cd /d C:\Users\20751\Desktop\异环\unidbg
set M2=C:\Users\20751\.m2\repository
set UNIDBG=D:\unidbg_classes
set CP=C:\Users\20751\Desktop\异环\unidbg;%UNIDBG%;%M2%\com\github\zhkl0228\unidbg-api\0.9.10-SNAPSHOT\unidbg-api-0.9.10-SNAPSHOT.jar;%M2%\com\github\zhkl0228\unicorn\1.0.15\unicorn-1.0.15.jar;%M2%\org\scijava\native-lib-loader\2.3.5\native-lib-loader-2.3.5.jar;%M2%\com\github\zhkl0228\capstone\3.1.8\capstone-3.1.8.jar;%M2%\net\java\dev\jna\jna\5.10.0\jna-5.10.0.jar;%M2%\com\github\zhkl0228\keystone\0.9.7\keystone-0.9.7.jar;%M2%\commons-codec\commons-codec\1.21.0\commons-codec-1.21.0.jar;%M2%\org\apache\commons\commons-collections4\4.5.0\commons-collections4-4.5.0.jar;%M2%\commons-io\commons-io\2.21.0\commons-io-2.21.0.jar;%M2%\com\alibaba\fastjson\1.2.83\fastjson-1.2.83.jar;%M2%\com\github\zhkl0228\demumble\1.0.4\demumble-1.0.4.jar;%M2%\net\dongliu\apk-parser\2.6.10\apk-parser-2.6.10.jar;%M2%\com\github\zhkl0228\unidbg-dynarmic\0.9.10-SNAPSHOT\unidbg-dynarmic-0.9.10-SNAPSHOT.jar;%M2%\com\github\zhkl0228\unidbg-hypervisor\0.9.10-SNAPSHOT\unidbg-hypervisor-0.9.10-SNAPSHOT.jar;%M2%\com\github\zhkl0228\unidbg-kvm\0.9.10-SNAPSHOT\unidbg-kvm-0.9.10-SNAPSHOT.jar;%M2%\com\github\zhkl0228\unidbg-unicorn2\0.9.10-SNAPSHOT\unidbg-unicorn2-0.9.10-SNAPSHOT.jar;%M2%\org\slf4j\slf4j-api\2.0.16\slf4j-api-2.0.16.jar;%M2%\junit\junit\4.13.2\junit-4.13.2.jar;%M2%\org\hamcrest\hamcrest-core\1.3\hamcrest-core-1.3.jar;%M2%\org\slf4j\slf4j-reload4j\2.0.16\slf4j-reload4j-2.0.16.jar;%M2%\ch\qos\reload4j\reload4j\1.2.22\reload4j-1.2.22.jar

if "%1"=="" goto :default
if "%1"=="kyc" goto :kyc
if "%1"=="probe" goto :probe
if "%1"=="combine" goto :combine
if "%1"=="jprobe" goto :jprobe
if "%1"=="secsdk" goto :secsdk
if "%1"=="memdump" goto :memdump
if "%1"=="segdump" goto :segdump
if "%1"=="rawdump" goto :rawdump
if "%1"=="tprt" goto :tprt
:default
echo [*] 编译 Demo...
javac -encoding UTF-8 -cp "%CP%" -d C:\Users\20751\Desktop\异环\unidbg C:\Users\20751\Desktop\异环\unidbg\Demo.java C:\Users\20751\Desktop\异环\unidbg\MyJni.java
if errorlevel 1 goto :err
echo [*] 运行 Demo...
java -cp "%CP%" Demo
goto :eof

:kyc
echo [*] 编译 KycgmDemo...
javac -encoding UTF-8 -cp "%CP%" -d C:\Users\20751\Desktop\异环\unidbg C:\Users\20751\Desktop\异环\unidbg\KycgmDemo.java
if errorlevel 1 goto :err
echo [*] 运行 KycgmDemo...
java -cp "%CP%" KycgmDemo
goto :eof

:probe
echo [*] 编译 ProbeMxcoreJava...
javac -encoding UTF-8 -cp "%CP%" -d C:\Users\20751\Desktop\异环\unidbg C:\Users\20751\Desktop\异环\unidbg\ProbeMxcoreJava.java C:\Users\20751\Desktop\异环\unidbg\MyJni.java
if errorlevel 1 goto :err
echo [*] 运行 ProbeMxcoreJava...
java -cp "%CP%" ProbeMxcoreJava
goto :eof

:combine
echo [*] 编译 CombinedProbe...
javac -encoding UTF-8 -cp "%CP%" -d C:\Users\20751\Desktop\异环\unidbg C:\Users\20751\Desktop\异环\unidbg\CombinedProbe.java C:\Users\20751\Desktop\异环\unidbg\MyJni.java
if errorlevel 1 goto :err
echo [*] 运行 CombinedProbe...
java -cp "%CP%" CombinedProbe
goto :eof

:jprobe
echo [*] JavasupportProbe...
javac -encoding UTF-8 -cp "%CP%" -d C:\Users\20751\Desktop\异环\unidbg C:\Users\20751\Desktop\异环\unidbg\JavasupportProbe.java C:\Users\20751\Desktop\异环\unidbg\MyJni.java
if errorlevel 1 goto :err
java -cp "%CP%" JavasupportProbe
goto :eof

:secsdk
echo [*] 编译 SecsdkProbe...
javac -encoding UTF-8 -cp "%CP%" -d C:\Users\20751\Desktop\异环\unidbg C:\Users\20751\Desktop\异环\unidbg\SecsdkProbe.java C:\Users\20751\Desktop\异环\unidbg\MyJni.java
if errorlevel 1 goto :err
echo [*] 运行 SecsdkProbe...
java -cp "%CP%" SecsdkProbe
goto :eof

:segdump
echo [*] 编译 SegDump...
javac -encoding UTF-8 -cp "%CP%" -d C:\Users\20751\Desktop\异环\unidbg C:\Users\20751\Desktop\异环\unidbg\SegDump.java C:\Users\20751\Desktop\异环\unidbg\MyJni.java
if errorlevel 1 goto :err
echo [*] 运行 SegDump...
java -cp "%CP%" SegDump
goto :eof

:memdump
echo [*] 编译 MemDump...
javac -encoding UTF-8 -cp "%CP%" -d C:\Users\20751\Desktop\异环\unidbg C:\Users\20751\Desktop\异环\unidbg\MemDump.java C:\Users\20751\Desktop\异环\unidbg\MyJni.java
if errorlevel 1 goto :err
echo [*] 运行 MemDump...
java -cp "%CP%" MemDump
goto :eof

:rawdump
echo [*] 编译 MemRawDump...
javac -encoding UTF-8 -cp "%CP%" -d C:\Users\20751\Desktop\异环\unidbg C:\Users\20751\Desktop\异环\unidbg\MemRawDump.java C:\Users\20751\Desktop\异环\unidbg\MyJni.java
if errorlevel 1 goto :err
echo [*] 运行 MemRawDump...
java -cp "%CP%" MemRawDump %2
goto :eof

:tprt
echo [*] 编译 TprtProbe...
javac -encoding UTF-8 -cp "%CP%" -d C:\Users\20751\Desktop\异环\unidbg C:\Users\20751\Desktop\异环\unidbg\TprtProbe.java C:\Users\20751\Desktop\异环\unidbg\MyJni.java
if errorlevel 1 goto :err
echo [*] 运行 TprtProbe...
java -cp "%CP%" TprtProbe
goto :eof

:err
echo [!] 编译失败
