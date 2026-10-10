#!/usr/bin/env python3
"""Owned-ROM modern SMC RTKit/key transport, two resets.
No firmware executes; this qualifies the model and claimed reset state only.
"""
import argparse, hashlib, importlib.util, json, struct, subprocess, tempfile, time
from pathlib import Path
spec=importlib.util.spec_from_file_location('transport',Path(__file__).with_name('test-apple-modern-sep-transport-qemu.py'))
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
m=t.mailbox;b=t.board
BASE=0x30c600000;DONE=0xfedcba9876543210
class ROM(m.ROM):
 def __init__(self,prestart):super().__init__();self.prestart=prestart
 def send(self,data,endpoint=0):self.write64(BASE+0x8800,data);self.write64(BASE+0x8808,endpoint)
 def receive(self,label,expected,endpoint=0):
  poll=len(self.words);self.read32(BASE+0x8114,23);self.mov(24,1|(1<<20));self.emit(0x6b1802ff);self.branch(poll,1)
  self.read64(BASE+0x8830,23);self.trace(label,expected,register=23)
  self.read64(BASE+0x8838,23);self.trace(label+'_endpoint_stamp',m.stamped(endpoint,1),register=23)
 def build(self):
  self.mov(20,m.SCRATCH);self.mov(0,m.NORMAL_SP);self.emit(0x9100001f);self.emit(0xd5034fdf);self.set('VBAR_EL2',m.BASE+0x4000)
  self.read32(BASE+0x8000,23);self.trace('reset_idle',0 if self.prestart else 3,register=23)
  self.read32(BASE+0x44,23);self.trace('reset_cpu_ctrl',16 if self.prestart else 0,register=23)
  if not self.prestart:self.write32(BASE+0x44,16)
  self.receive('hello',(1<<52)|(12<<16)|3)
  self.send((2<<52)|(12<<16)|12)
  self.receive('map_control',(8<<52)|3)
  self.send((8<<52)|1)
  self.receive('map_smc_keys',(8<<52)|(1<<51)|(1<<32)|1)
  self.send((8<<52)|(1<<51)|(1<<32))
  self.receive('power_ack',(7<<52)|32)
  self.send((11<<52)|32);self.receive('ap_power_ack',(11<<52)|32)
  self.read64(0x30c050000,23);self.trace('core_loaded_bit',1,register=23)
  self.read64(0x30de00000,23);self.trace('reset_sram',0,register=23)
  self.send(0x17,32);self.receive('sram_address',0x30de00000,32)
  self.send((int.from_bytes(b'RGEN','big')<<32)|(1<<16)|(0x46<<8)|0x10,32)
  self.receive('rgen_read',(3<<32)|(1<<16)|(0x46<<8),32)
  self.send((int.from_bytes(b'RGEN','big')<<32)|(0x47<<8)|0x13,32)
  self.receive('rgen_info',0x47<<8,32)
  self.read64(0x30de00000,23);self.trace('info_sram',int.from_bytes(b'\x01ui8 \x80\x00\x00','little'),register=23)
  self.send((int.from_bytes(b'ZZZZ','big')<<32)|(4<<16)|(0x48<<8)|0x10,32)
  self.receive('unknown_key_refusal',(0x48<<8)|0x84,32)
  self.send((int.from_bytes(b'RGEN','big')<<32)|(1<<16)|(0x49<<8)|0x10,32)
  self.receive('rgen_after_refusal',(3<<32)|(1<<16)|(0x49<<8),32)
  self.mov(0,DONE);self.trace('completion',DONE);self.branch(len(self.words))
  for offset in range(0x4000,0x4800,0x80):
   self.at(offset);self.mov(0,1);self.store(0,0x500);self.emit(m.sysreg('ESR_EL2',0,True));self.store(0,0x508);self.branch(len(self.words))
  return b''.join(struct.pack('<I',word) for word in self.words)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def available():return int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))
def run(a,mode):
 out=a.out/mode;out.mkdir();pre=mode=='v6-prestarted';rom=ROM(pre);content=rom.build();rp=out/'owned.rom';rp.write_bytes(content);zp=out/'zero.bin';zp.write_bytes(bytes(0x510));logp=out/'qemu.log'
 assets=[a.components/n for n in b.ASSETS];assets[3]=a.dtree;before={str(p):digest(p) for p in assets};binaryhash=digest(a.binary)
 machine='apple-modern,'+','.join(n+'='+str(p) for n,p in zip(['bootkc','sptm','txm','dtree','tc'],assets))+',prepare-only=on,modern-aic=on,aic-record-irq-config=on,adt-compat-restore=smc,modern-smc=on'
 argv=[str(a.binary),'-M',machine,'-m','8G','-smp','1','-nodefaults','-display','none','-serial','none','-monitor','none','-device',f'loader,file={rp},addr={m.BASE},cpu-num=0,force-raw=true','-device',f'loader,file={zp},addr={m.SCRATCH},force-raw=true','-S','-qmp','stdio']
 report={'passed':False,'firmware_executed':False,'guest_driver_exercised':False,'mode':mode,'argv':argv,'binary_sha256':binaryhash,'owned_rom_sha256':digest(rp),'component_hashes_before':before,'passes':[]};process=qmp=None;start=time.monotonic()
 report['mem_available_start_kb']=available();report['mem_available_min_kb']=report['mem_available_start_kb']
 try:
  assert report['mem_available_start_kb']>=7000000,'Below project start memory floor'
  with tempfile.TemporaryDirectory() as tmp,logp.open('xb') as log:
   process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,bufsize=0,preexec_fn=m.child_limits)
   def guard():
    left=60-(time.monotonic()-start);avail=available();report['mem_available_min_kb']=min(report['mem_available_min_kb'],avail);assert avail>=900000,'Below project abort memory floor';assert left>0 and logp.stat().st_size<(1<<20);return left
   qmp=t.QMP(None,guard,process)
   for iteration in range(2):
    if iteration:qmp.request('system_reset')
    regs=b.parse_registers(qmp.request('human-monitor-command',{'command-line':'info registers'}));assert regs['PC']==m.BASE and regs['PSTATE']&15==9
    assert not qmp.request('query-status')['running']
    dp=Path(tmp)/'dump';qmp.request('pmemsave',{'val':m.BASE,'size':len(content),'filename':str(dp)});assert dp.read_bytes()==content
    qmp.request('pmemsave',{'val':m.SCRATCH,'size':0x510,'filename':str(dp)});assert dp.read_bytes()==bytes(0x510)
    qmp.request('cont');deadline=time.monotonic()+12
    while True:
     guard();qmp.request('stop');qmp.request('pmemsave',{'val':m.SCRATCH,'size':len(rom.expected)*8,'filename':str(dp)});raw=dp.read_bytes()
     if struct.unpack_from('<Q',raw,(len(rom.expected)-1)*8)[0]==DONE:break
     assert time.monotonic()<deadline,'Owned handshake did not complete';qmp.request('cont');time.sleep(.03)
    observed={k:struct.unpack_from('<Q',raw,i*8)[0] for i,k in enumerate(rom.expected)};assert observed==rom.expected,(observed,rom.expected)
    qmp.request('pmemsave',{'val':m.SCRATCH+0x500,'size':16,'filename':str(dp)});assert dp.read_bytes()==bytes(16)
    report['passes'].append({'iteration':iteration,'observed':observed,'completed':True})
   qmp.request('quit');assert process.wait(timeout=10)==0;process=None;report['passed']=True
 except Exception as e:report['error']=str(e)
 finally:
  if process:process.kill();process.wait(timeout=10)
  if qmp:qmp.close()
  after={str(p):digest(p) for p in assets};report['component_hashes_after']=after
  if after!=before or digest(a.binary)!=binaryhash:report['passed']=False;report['error']='Input changed'
  report['elapsed_seconds']=time.monotonic()-start;(out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 return report
p=argparse.ArgumentParser();p.add_argument('--binary',required=True,type=Path);p.add_argument('--components',required=True,type=Path);p.add_argument('--out',required=True,type=Path);p.add_argument('--dtree',required=True,type=Path);a=p.parse_args()
a.dtree=a.dtree.resolve();a.binary=a.binary.resolve();a.components=a.components.resolve();a.out=a.out.resolve();a.out.mkdir(exist_ok=False,parents=True)
r=[run(a,'v6')];result={'passed':all(v['passed'] for v in r),'firmware_executed':False,'modern_endpoint_name_measured':False,'modern_input_acceptance_qualified':False,'arms':r};(a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'passed':result['passed'],'errors':[v.get('error') for v in r]}));raise SystemExit(0 if result['passed'] else 1)
