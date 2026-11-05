import os
from validation_matrix import root, out, run, HarnessGenerator
import shutil
# Build Java directly against installed Ghidra libraries, without Gradle/network.
jars=list((root.parent/'ghidra_11.4.3_PUBLIC'/'Ghidra').rglob('*.jar'))
javaout=out/'java';javaout.mkdir(exist_ok=True)
r=run([os.path.join(os.environ['JAVA_HOME'], 'bin/javac'),'-proc:none','-cp',os.pathsep.join(map(str,jars)),'-d',str(javaout)]+list(map(str,(root/'src/main/java').rglob('*.java'))))
print('JAVAC',r.returncode,r.stderr);(out/'java-build.log').write_text(r.stdout+r.stderr)
# Compile JNI stub on the host with NDK JNI declarations, then run ASan.
d=out/'jni_asan';d.mkdir(exist_ok=True)
shutil.copy(os.path.join(os.environ['ANDROID_NDK_HOME'], 'toolchains/llvm/prebuilt/darwin-x86_64/sysroot/usr/include/jni.h'),d/'jni.h')
(d/'jni_stub.h').write_text(HarnessGenerator().generate_jni_header())
(d/'probe.c').write_text('#include "jni_stub.h"\nint main(void){JNIEnv e=fz_jni_env();jstring s=e->NewStringUTF(&e,"abc");char buf[8];e->GetStringUTFRegion(&e,s,-1,1,buf);return 0;}\n')
r=run(['clang','-I'+str(d),'-g','-fsanitize=address',str(d/'probe.c'),'-o',str(d/'probe')]);print('JNI COMPILE',r.returncode,r.stderr)
if r.returncode==0:
 r=run([str(d/'probe')]);print('JNI ASAN',r.returncode,r.stderr[:1800]);(out/'jni-asan.log').write_text(r.stderr)
# Stub adb, do not touch a device: exercise macOS system bash launcher.
d=out/'shell';d.mkdir(exist_ok=True)
(d/'run.sh').write_text(HarnessGenerator().generate_run_script('probe','libprobe.so','afl'))
(d/'harness_probe').touch();(d/'libprobe.so').touch()
(d/'adb').write_text('#!/bin/sh\nif [ "$2" = getprop ]; then echo arm64-v8a; fi\nexit 0\n');(d/'adb').chmod(0o755)
r=run(['/bin/bash',str(d/'run.sh')],env={**os.environ,'PATH':str(d)+':/usr/bin:/bin'});print('SHELL',r.returncode,r.stderr);(out/'shell.log').write_text(r.stdout+r.stderr)
