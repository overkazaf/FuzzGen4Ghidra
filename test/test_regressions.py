"""Compile and execute generated harnesses; never substitute string checks for calls."""
import os
from pathlib import Path
import platform
import shutil
import subprocess

import pytest

from fuzzgen4ghidra_engine.engine import FuzzGenEngine
from fuzzgen4ghidra_engine.harness import HarnessGenerator
from fuzzgen4ghidra_engine.params import recover_params_from_ghidra


def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30, **kwargs)


def sig(*pairs):
    return {"params": [{"name": n, "type": t, "size": 8 if '*' in t else 4}
                       for n, t in pairs]}


@pytest.fixture
def cc():
    compiler = shutil.which('clang') or shutil.which('cc')
    if not compiler:
        pytest.skip('C compiler unavailable')
    return compiler


@pytest.mark.parametrize('fmt', ['afl', 'libfuzzer'])
@pytest.mark.parametrize('signature,body', [
    (sig(('buf', 'byte *'), ('len', 'int'), ('flags', 'int')),
     'assert(len == 28 && flags == 0x04030201 && buf[0] == 5);'),
    (sig(('buf', 'const unsigned char *'), ('len', 'int')),
     'assert(len == 32 && buf[0] == 1);'),
    (sig(('buf', 'byte *'), ('option', 'int'), ('len', 'int')),
     'assert(len == 28 && option == 0x04030201);'),
    (sig(('a', 'byte *'), ('a_len', 'int'), ('b', 'byte *'), ('b_len', 'int')),
     'assert(a_len == 16 && b_len == 16 && a[0] == 1 && b[0] == 17);'),
    (sig(('target', 'int')), 'assert(target == 0x04030201);'),
    (sig(('cb', 'code *')), 'assert(cb == 0);'),
    (sig(('ctx', 'parser_ctx *')), 'assert(ctx != 0);'),
    (sig(('flag', 'bool')), '(void)flag;'),
])
def test_generated_call(tmp_path, cc, fmt, signature, body):
    lib = 'libprobe.dylib' if platform.system() == 'Darwin' else 'libprobe.so'
    engine = FuzzGenEngine()
    engine.generate_harness(0x1000, 'probe', signature, lib, fmt,
                            output_dir=str(tmp_path), call_mode='dlsym')
    # A separate oracle declaration avoids relying on generator type recovery.
    mapping = {'byte *': 'unsigned char *', 'code *': 'void (*cb)(void)'}
    declarations = []
    for p in signature['params']:
        declarations.append(mapping['code *'] if p['type'] == 'code *'
                            else mapping.get(p['type'], p['type']) + ' ' + p['name'])
    (tmp_path/'probe.c').write_text(
        '#include <assert.h>\n#include <stdbool.h>\ntypedef struct parser_ctx parser_ctx;\n'
        + 'int probe(' + ', '.join(declarations) + '){' + body + 'return 0;}')
    shared = ['-dynamiclib'] if platform.system() == 'Darwin' else ['-shared', '-fPIC']
    r = run([cc, *shared, str(tmp_path/'probe.c'), '-o', str(tmp_path/lib)])
    assert r.returncode == 0, r.stderr
    cmd = [cc, '-std=c11', '-D_GNU_SOURCE', str(tmp_path/'harness_probe.c')]
    if fmt == 'libfuzzer':
        (tmp_path/'driver.c').write_text(
            '#include <stdint.h>\n#include <stddef.h>\n'
            'int LLVMFuzzerTestOneInput(const uint8_t*,size_t);\n'
            'int main(void){uint8_t input[32];for(int i=0;i<32;i++)input[i]=i+1;'
            'return LLVMFuzzerTestOneInput(input,32);}')
        cmd += [str(tmp_path/'driver.c')]
    cmd += ['-o', str(tmp_path/'harness'), '-ldl']
    r = run(cmd)
    assert r.returncode == 0, r.stderr
    (tmp_path/'input').write_bytes(bytes(range(1,33)))
    r = run([str(tmp_path/'harness'), 'input'], cwd=tmp_path)
    assert r.returncode == 0, r.stderr


def test_length_pairing():
    params = recover_params_from_ghidra(sig(('a','byte *'),('option','int'),
        ('b','byte *'),('b_len','unsigned int'),('a_len','int')))
    assert params[0].length_param == 4
    assert params[2].length_param == 3


@pytest.fixture
def jni_header():
    ndk = os.environ.get('ANDROID_NDK_HOME')
    if not ndk:
        pytest.skip('Set ANDROID_NDK_HOME for JNI regression')
    headers = list(Path(ndk).glob('toolchains/llvm/prebuilt/*/sysroot/usr/include/jni.h'))
    assert headers
    return headers[0]


def test_jni_invalid_regions(tmp_path, cc, jni_header):
    shutil.copy(jni_header, tmp_path/'jni.h')
    (tmp_path/'jni_stub.h').write_text(HarnessGenerator().generate_jni_header())
    (tmp_path/'probe.c').write_text('''
#include <assert.h>
#include <limits.h>
#include "jni_stub.h"
int main(void) {
    JNIEnv env = fz_jni_env();
    jstring s = env->NewStringUTF(&env, "abc");
    char buf[8] = {42};
    env->GetStringUTFRegion(&env, s, -1, 1, buf);
    assert(buf[0] == 42 && env->ExceptionCheck(&env));
    assert(env->ExceptionOccurred(&env) != NULL);
    env->ExceptionClear(&env);
    assert(!env->ExceptionCheck(&env));
    env->GetStringUTFRegion(&env, s, 1, INT_MAX, buf);
    assert(env->ExceptionCheck(&env));
    env->ExceptionClear(&env);
    env->GetStringUTFRegion(&env, s, 0, 3, buf);
    assert(!env->ExceptionCheck(&env) && memcmp(buf, "abc", 3) == 0);
    jbyteArray arr = env->NewByteArray(&env, 3);
    env->SetByteArrayRegion(&env, arr, 1, INT_MAX, (jbyte*)buf);
    assert(env->ExceptionCheck(&env));
    env->ExceptionClear(&env);
    env->GetByteArrayRegion(&env, arr, 1, INT_MAX, (jbyte*)buf);
    assert(env->ExceptionCheck(&env));
    return 0;
}
''')
    r = run([cc, '-I'+str(tmp_path), '-fsanitize=address,undefined',
             str(tmp_path/'probe.c'), '-o', str(tmp_path/'probe')])
    assert r.returncode == 0, r.stderr
    r = run([str(tmp_path/'probe')], env={**os.environ, 'ASAN_OPTIONS':'detect_leaks=0'})
    assert r.returncode == 0, r.stderr


def test_device_script_system_bash(tmp_path):
    (tmp_path/'run.sh').write_text(HarnessGenerator().generate_run_script('probe','libprobe.so','afl'))
    for name in ['harness_probe','libprobe.so','libdependency.so']:
        (tmp_path/name).touch()
    (tmp_path/'seeds').mkdir()
    (tmp_path/'seeds/seed').write_bytes(b'abc')
    log = tmp_path/'adb.log'
    (tmp_path/'adb').write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$ADB_LOG"\n'
                               'if [ "$2" = getprop ]; then echo arm64-v8a; fi\n')
    (tmp_path/'adb').chmod(0o755)
    r = run(['/bin/bash', str(tmp_path/'run.sh')], env={**os.environ,
            'PATH': str(tmp_path)+':/usr/bin:/bin', 'ADB_LOG':str(log)})
    assert r.returncode == 0 and not r.stderr, r.stderr
    assert 'libdependency.so' in log.read_text()
    assert sum('push' in line and 'libprobe.so' in line for line in log.read_text().splitlines()) == 1


@pytest.mark.parametrize('type_name', ['const byte*', 'byte const *', 'byte * const'])
def test_qualified_buffer(type_name):
    from fuzzgen4ghidra_engine.models import ParamType
    params = recover_params_from_ghidra(sig(('data', type_name), ('dataLen', 'int')))
    assert params[0].type == ParamType.BUFFER
    assert params[0].length_param == 1
    assert 'byte' not in params[0].c_type


def test_builtin_pointer_is_not_opaque():
    params = recover_params_from_ghidra(sig(('argv', 'char **')))
    header = HarnessGenerator().generate_types_header([], params)
    assert 'typedef struct char' not in header


@pytest.mark.parametrize('fmt', ['afl', 'libfuzzer'])
def test_jni_buffer_call(tmp_path, cc, jni_header, fmt):
    # JNI's synthetic env/thiz must never steal the fuzz buffer's length.
    shutil.copy(jni_header, tmp_path/'jni.h')
    lib = 'libprobe.dylib' if platform.system() == 'Darwin' else 'libprobe.so'
    FuzzGenEngine().generate_harness(0x1000, 'probe', sig(
        ('env', 'void *'), ('thiz', 'void *'), ('data', 'byte *'), ('len', 'int')),
        lib, fmt, output_dir=str(tmp_path), target_platform='android',
        jni_mode='env', run_jni_onload=False, call_mode='dlsym')
    (tmp_path/'probe.c').write_text('#include <assert.h>\n#include "jni.h"\n'
        'int probe(JNIEnv *env,jobject thiz,unsigned char *data,int len){'
        'assert(env && thiz && len==4 && data[0]==1);return 0;}')
    shared = ['-dynamiclib'] if platform.system() == 'Darwin' else ['-shared', '-fPIC']
    r = run([cc, *shared, str(tmp_path/'probe.c'), '-o', str(tmp_path/lib)])
    assert r.returncode == 0, r.stderr
    cmd = [cc, '-D_GNU_SOURCE', '-I'+str(tmp_path), str(tmp_path/'harness_probe.c')]
    if fmt == 'libfuzzer':
        (tmp_path/'driver.c').write_text('#include <stdint.h>\n#include <stddef.h>\n'
            'int LLVMFuzzerTestOneInput(const uint8_t*,size_t);'
            'int main(void){uint8_t b[]={1,2,3,4};return LLVMFuzzerTestOneInput(b,4);}')
        cmd += [str(tmp_path/'driver.c')]
    r = run(cmd + ['-o', str(tmp_path/'harness'), '-ldl'])
    assert r.returncode == 0, r.stderr
    (tmp_path/'input').write_bytes(bytes([1,2,3,4]))
    r = run([str(tmp_path/'harness'), 'input'], cwd=tmp_path)
    assert r.returncode == 0, r.stderr
