import sys, pathlib, subprocess, json, os
root=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(root/'python'))
from fuzzgen4ghidra_engine.engine import FuzzGenEngine
from fuzzgen4ghidra_engine.harness import HarnessGenerator
out=pathlib.Path(os.environ.get('FUZZGEN_VALIDATION_OUT', '/private/tmp/fuzzgen-validation-20261105'));out.mkdir(parents=True, exist_ok=True)
results=[]
def run(cmd, **kw): return subprocess.run(cmd,text=True,capture_output=True,timeout=60,**kw)
def params(*args): return {'params':[{'name':n,'type':t,'size':s} for n,t,s in args]}
cases={
'basic':(params(('buf','byte *',8),('len','int',4)), 'int probe(unsigned char *buf,int len){printf("%d:%u\\n",len,buf?buf[0]:0);return 0;}'),
'scalar_after_buffer':(params(('buf','byte *',8),('len','int',4),('flags','int',4)), 'int probe(unsigned char *buf,int len,int flags){printf("%d:%d\\n",len,flags);return 0;}'),
'multiple_buffers':(params(('a','byte *',8),('a_len','int',4),('b','byte *',8),('b_len','int',4)), 'int probe(unsigned char*a,int al,unsigned char*b,int bl){printf("%d:%d:%d\\n",al,bl,b!=NULL);return 0;}'),
'buffer_named_length':(params(('buf','byte *',8),('buf_len','int',4)), ''),
'local_collision':(params(('target','int',4)),''),
'const_buffer':(params(('buf','const unsigned char *',8),('len','int',4)), 'int probe(const unsigned char *buf,int len){printf("%d\\n",len);return 0;}'),
'bool':(params(('flag','bool',1)),''),
'callback':(params(('cb','code *',8)),''),
'custom_struct':(params(('ctx','parser_ctx *',8)),''),
'count_false_match':(params(('buf','byte *',8),('option','int',4),('len','int',4)), 'int probe(unsigned char*buf,int option,int len){printf("%d:%d\\n",option,len);return 0;}'),
}
def main():
    for name,(sig,target) in cases.items():
     for fmt in ['afl','libfuzzer']:
      d=out/(name+'_'+fmt);d.mkdir(exist_ok=True)
      FuzzGenEngine().generate_harness(0x1000,'probe',sig,'libprobe.dylib',fmt,output_dir=str(d),call_mode='dlsym')
      c=run(['clang','-fsyntax-only',str(d/'harness_probe.c')])
      rec={'case':name,'fmt':fmt,'compile':c.returncode,'error':c.stderr[:1800]}
      if c.returncode==0 and target and fmt=='afl':
       (d/'target.c').write_text('#include <stdio.h>\n'+target)
       assert run(['clang','-dynamiclib',str(d/'target.c'),'-o',str(d/'libprobe.dylib')]).returncode==0
       assert run(['clang',str(d/'harness_probe.c'),'-o',str(d/'harness')]).returncode==0
       (d/'input').write_bytes(bytes(range(1,33)))
       r=run([str(d/'harness'),'input'],cwd=d);rec.update(runtime=r.returncode,stdout=r.stdout,stderr=r.stderr)
      results.append(rec)
    ndk=pathlib.Path(os.environ['ANDROID_NDK_HOME'])/'toolchains/llvm/prebuilt/darwin-x86_64'
    for arch in ['aarch64-linux-android','armv7a-linux-androideabi','x86_64-linux-android','i686-linux-android']:
     for fmt in ['afl','libfuzzer']:
      for jni in ['off','env','onload']:
       d=out/(arch+'_'+fmt+'_'+jni);d.mkdir(exist_ok=True)
       FuzzGenEngine().generate_harness(0x1000,'probe',{'params':[]},'libprobe.so',fmt,output_dir=str(d),target_platform='android',jni_mode=jni)
       cmd=[str(ndk/'bin'/(arch+'21-clang')), '-fsanitize=address,undefined']
       if fmt=='libfuzzer':cmd+=['-fsanitize=fuzzer']
       r=run(cmd+[str(d/'harness_probe.c'),'-o',str(d/'harness'),'-ldl','-lm'])
       results.append({'case':arch,'fmt':fmt,'jni':jni,'compile':r.returncode,'error':r.stderr[:1800]})
    (out/'results.json').write_text(json.dumps(results,indent=2))
    for r in results:print(r['case'],r['fmt'],r.get('jni',''),r['compile'],r.get('stdout','').strip(),r.get('error','')[:130].replace('\n',' '))

if __name__ == '__main__':
    main()
