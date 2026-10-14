#!/usr/bin/env python3
"""Owned ARM64 CPU -> ANS tags/TCBs -> normal NVMe -> raw block backend.

No Apple firmware executes. Kill/reopen follows an acknowledged native NVMe
flush; this qualifies process-crash persistence, not host power-loss behavior.
"""
import argparse, hashlib, importlib.util, json, os, shutil, struct, subprocess, tempfile, time
from pathlib import Path
import sys
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('ans_helpers',Path(__file__).with_name('test-apple-modern-pmgr-qemu.py'))
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
mb,board=h.mailbox,h.board
require=h.require
BASE=mb.BASE;RESULT=mb.SCRATCH
WRAP=0x389600000;BAR=0x38dcc0000;SECURE=0x3cdcc0000
DMA=BASE+0x40000
ASQ=DMA;ACQ=DMA+0x4000;IOSQ=DMA+0x8000;IOCQ=DMA+0xc000
ATCB=DMA+0x10000;ITCB=DMA+0x14000;TX=DMA+0x18000;RX=DMA+0x1c000
DONE=0xa45b10c0f15a0e55
PATTERN=hashlib.shake_256(b'owned-native-ans-persistent-block-v1').digest(4096)
def sha(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

class ROM(mb.ROM):
 def __init__(self,mode):
  super().__init__();self.mode=mode;self.cq_head=[0,0];self.phase=[1,1]
 def trace(self,*args,**kwargs):
  super().trace(*args,**kwargs)
  self.write64(RESULT+0xf00,len(self.expected))
 def check(self,label,addr,value):
  self.read32(addr,23);self.trace(label,value,register=23)
 def poll_value(self,addr,value):
  self.mov(22,value);loop=len(self.words);self.read32(addr,23)
  self.emit(0xeb1602ff);self.branch(loop,1) # cmp x23,x22; b.ne
 def receive(self,label,expected):
  loop=len(self.words);self.read64(WRAP+0x8830,23);self.read64(WRAP+0x8838,24)
  self.emit(0xf10002ff);self.branch(loop,0) # cmp x23,#0; b.eq
  self.trace(label,expected,register=23)
 def send(self,value):
  self.write64(WRAP+0x8800,value);self.write64(WRAP+0x8808,0)
 def blob(self,pa,data):
  require(len(data)%8==0,'owned record aligned')
  for i in range(0,len(data),8):self.write64(pa+i,int.from_bytes(data[i:i+8],'little'))
 def prepare_cmd(self,qid,op,tag=7,prp=0,prp2=0,nsid=0,cdw10=0,cdw11=0,cdw12=0,crypto=False):
  cmd=struct.pack('<BBHIQQQQ6I',op,0,tag,nsid,0,0,prp,prp2,cdw10,cdw11,cdw12,0,0,0)
  tcb=bytearray(128);tcb[1]=(2 if op&1 else 1) if prp else 0;tcb[2]=tag
  struct.pack_into('<I',tcb,4,cdw12);struct.pack_into('<Q',tcb,24,prp)
  struct.pack_into('<Q',tcb,32,prp2)
  if crypto:tcb[64]=1
  self.blob((IOSQ if qid else ASQ)+tag*64,cmd)
  self.blob((ITCB if qid else ATCB)+tag*128,tcb)
 def submit(self,qid,label,tag=7,error=0,duplicate=False,irq=False):
  cq=IOCQ if qid else ACQ;head=self.cq_head[qid];phase=self.phase[qid]
  self.write32(BAR+(0x24910 if qid else 0x2490c),tag)
  if duplicate:self.write32(BAR+(0x24910 if qid else 0x2490c),tag)
  loop=len(self.words);self.read32(cq+head*16+12,23)
  self.emit(0x531042f8) # ubfx w24,w23,#16,#1
  self.emit(0x7100031f|(phase<<10));self.branch(loop,1) # cmp w24,#phase
  expected=None if error is None else (((error<<1)|phase)<<16)|tag
  self.trace(label,expected,register=23)
  if irq:
   self.read32(mb.AIC_BASE+mb.EVENT,23)
   self.trace('nvme_irq_event',mb.EVENT_IRQ|1039,register=23)
  self.write32(BAR+0x28118,tag)
  self.check(label+'_invalidated',BAR+0x28120,0)
  head+=1
  if head==64:head=0;self.phase[qid]^=1
  self.cq_head[qid]=head
  self.write32(SECURE+(0x100c if qid else 0x1004),head)
 def build(self):
  self.mov(20,RESULT);self.mov(0,mb.NORMAL_SP);self.emit(0x9100001f)
  self.emit(0xd5034fdf) # DAIF masked; actual CPU polls MMIO and DMA
  self.check('boot_not_ready_before_rtkit',BAR+0x1300,0)
  self.write32(WRAP+0x8114,1);self.write32(WRAP+0x44,16)
  self.receive('rtkit_hello',0x100000000c0003)
  self.send(0x200000000c000c)
  self.receive('rtkit_endpoint_map',0x88000000000003)
  self.send(0x80000000000000)
  self.receive('rtkit_power_ack',0x70000000000020)
  self.check('boot_ready_after_rtkit',BAR+0x1300,0xde71ce55)
  self.write32(BAR+0x24908,1);self.write32(BAR+0x28100,63)
  # Low/high writes as used by SPTM; standard registers through secure alias.
  for pa,val in [(BAR+0x28108,ATCB),(BAR+0x28110,ITCB),
                 (SECURE+0x28,ASQ),(SECURE+0x30,ACQ)]:
   self.write32(pa,val&0xffffffff);self.write32(pa+4,val>>32)
  self.write32(SECURE+0x24,0x003f003f)
  self.write32(SECURE+0x14,0x00460001)
  self.check('controller_ready',SECURE+0x1c,1)
  self.prepare_cmd(0,6,tag=63,prp=RX,cdw10=1)
  self.submit(0,'identify_controller',tag=63)
  self.check('identify_namespace_limit',RX+516,16)
  self.prepare_cmd(0,5,tag=63,prp=IOCQ,cdw10=(63<<16)|1,cdw11=3)
  self.submit(0,'create_cq',tag=63)
  self.prepare_cmd(0,1,tag=63,prp=IOSQ,cdw10=(63<<16)|1,cdw11=(1<<16)|1)
  self.submit(0,'create_sq',tag=63)
  self.write32(mb.AIC_BASE+mb.GLBCFG,1);self.unmask(1039)
  if self.mode!='recovery':
   self.prepare_cmd(1,1,prp=TX,nsid=1,cdw10=3)
   self.submit(1,'write_block',error=None if self.mode=='readonly' else 0,irq=True)
   self.prepare_cmd(1,1,prp=TX,prp2=TX+4096,nsid=1,cdw10=7,cdw12=1)
   self.submit(1,'write_two_blocks',error=None if self.mode=='readonly' else 0)
  self.prepare_cmd(1,0,nsid=1)
  self.submit(1,'flush_backend')
  self.prepare_cmd(1,2,prp=RX,nsid=1,cdw10=3)
  self.submit(1,'read_block',duplicate=True)
  self.read64(RX,23);self.trace('read_first_word',int.from_bytes(PATTERN[:8],'little'),register=23)
  self.read64(RX+4088,23);self.trace('read_last_word',int.from_bytes(PATTERN[-8:],'little'),register=23)
  # Reuse one tag across a CQ phase wrap; index 7 differs from the ring tail.
  for i in range(66):self.submit(1,'wrap_read_'+str(i))
  self.prepare_cmd(1,2,prp=RX,prp2=RX+4096,nsid=1,cdw10=7,cdw12=1)
  self.submit(1,'read_two_blocks')
  self.prepare_cmd(1,1,prp=BAR,nsid=1,cdw10=5)
  self.submit(1,'mmio_dma_write_refused',error=0x4002)
  self.prepare_cmd(1,1,prp=TX,prp2=BAR,nsid=1,cdw10=5,cdw12=1)
  self.submit(1,'partial_dma_write_refused',error=0x4002)
  self.prepare_cmd(1,1,prp=TX,nsid=1,cdw10=5)
  self.write32(ITCB+7*128+4,1) # Command and authorization disagree on transfer length.
  self.submit(1,'tcb_length_mismatch_refused',error=0x4002)
  self.prepare_cmd(1,1,prp=TX,nsid=1,cdw10=6,crypto=True)
  self.submit(1,'unsupported_crypto_write_refused',error=0x4002)
  self.mov(0,DONE);self.trace('completion',DONE);self.branch(len(self.words))
  raw=struct.pack('<'+'I'*len(self.words),*self.words)
  require(len(raw)<0x10000,'owned ROM must not overlap results')
  return raw

def run_case(binary,assets,out,backing,mode):
 out.mkdir(exist_ok=False)
 rom=ROM(mode);raw=rom.build();(out/'owned-ans.rom').write_bytes(raw)
 data=bytearray(0x20000)
 pattern=hashlib.shake_256(b'distinct-write-must-fail-on-read-only-media').digest(4096) if mode=='readonly' else PATTERN
 data[TX-DMA:TX-DMA+8192]=pattern*2
 (out/'owned-dma.bin').write_bytes(data);(out/'zero-results.bin').write_bytes(bytes(4096))
 machine='apple-modern,'+','.join(k+'='+str(assets[v]) for k,v in zip(('bootkc','sptm','txm','dtree','tc'),board.ASSETS))
 machine+=',prepare-only=on,modern-aic=on,modern-ans=on'
 args=[str(binary),'-M',machine,'-m','8G','-smp','1','-nodefaults','-display','none','-serial','none','-monitor','none',
       '-blockdev',f'driver=file,filename={backing},node-name=native-file,read-only={"on" if mode=="readonly" else "off"},cache.no-flush=off',
       '-blockdev',f'driver=raw,file=native-file,node-name=native-disk,read-only={"on" if mode=="readonly" else "off"}',
       '-device','nvme-ns,drive=native-disk,bus=modern-ans-nvme,nsid=1,logical_block_size=4096,physical_block_size=4096',
       '-device',f'loader,file={out}/owned-ans.rom,addr={BASE},cpu-num=0,force-raw=true',
       '-device',f'loader,file={out}/owned-dma.bin,addr={DMA},force-raw=true',
       '-device',f'loader,file={out}/zero-results.bin,addr={RESULT},force-raw=true','-S','-qmp','stdio']
 report={'passed':False,'mode':mode,'argv':args,'binary_sha256':sha(binary),'script_sha256':sha(__file__),
         'firmware_executed':False,'ios_driver_qualified':False,'child_reaped':False,'inputs_before':{k:sha(p) for k,p in assets.items()}}
 p=qmp=None;start=time.monotonic()
 def guard():
  require(time.monotonic()-start<50,'owned CPU gate deadline')
  require((out/'emulator.log').stat().st_size<4<<20,'owned gate log bound')
  return 50-(time.monotonic()-start)
 try:
  with (out/'emulator.log').open('xb') as log:
   p=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,bufsize=0,start_new_session=True)
   report['pid']=p.pid;report['start_ticks']=Path(f'/proc/{p.pid}/stat').read_text().rsplit(')',1)[1].split()[19]
   qmp=h.QMP(None,guard,p)
   require(qmp.request('qom-get',{'path':'/machine','property':'prepare-only'}) is True,'firmware stopped')
   try:qmp.request('qom-set',{'path':'/machine','property':'modern-ans','value':False})
   except RuntimeError as e:
    require('properties are fixed after initialization' in str(e),'specific immutable-property refusal')
    report['immutable_option']=str(e)
   else:raise RuntimeError('mutable board option')
   try:qmp.request('migrate',{'uri':'file:'+str(out/'migration.refused')})
   except RuntimeError as e:
    require('non-migratable' in str(e),'migration fails for device state')
    report['migration_rejection']=str(e)
   else:raise RuntimeError('unsupported migration admitted')
   with tempfile.TemporaryDirectory(prefix='ans-prelaunch-') as temp:
    target=Path(temp)/'verify'
    for pa,expected in [(BASE,raw),(RESULT,bytes(4096)),(DMA,bytes(data))]:
     qmp.request('pmemsave',{'val':pa,'size':len(expected),'filename':str(target)})
     require(target.read_bytes()==expected,'exact owned prelaunch CPU/DMA/result bytes')
   report['owned_prelaunch_bytes_verified']=True
   qmp.request('cont')
   with tempfile.TemporaryDirectory(prefix='owned-ans-') as temp:
    target=Path(temp)/'results'
    while True:
     guard();time.sleep(.1)
     qmp.request('stop');qmp.request('pmemsave',{'val':RESULT,'size':4096,'filename':str(target)})
     result=target.read_bytes();(out/'results.bin').write_bytes(result)
     values=list(struct.unpack_from('<'+'Q'*len(rom.expected),result))
     progress=struct.unpack_from('<Q',result,0xf00)[0]
     require(progress<=len(rom.expected),'CPU progress bound')
     for (k,expected),got in zip(list(rom.expected.items())[:progress],values):
      if expected is None:require(got>>17!=0,'negative NVMe completion '+k)
      else:require(got==expected,'CPU mismatch '+k+': '+hex(got)+' != '+hex(expected))
     if values[-1]==DONE:break
     report['last_values']=dict(zip(rom.expected,values))
     report['last_registers']=qmp.request('human-monitor-command',{'command-line':'info registers'})
     qmp.request('cont')
    got=dict(zip(rom.expected,values));report['cpu_checks']=got
    for k,expected in rom.expected.items():
     if expected is None: require(got[k]>>17!=0,'negative must report NVMe error: '+k)
     else:require(got[k]==expected,'CPU mismatch '+k+': '+hex(got[k])+' != '+hex(expected))
    qmp.request('pmemsave',{'val':RX,'size':8192,'filename':str(target)})
    require(target.read_bytes()==PATTERN*2,'every data byte read by controller')
    report['readback_sha256']=hashlib.sha256(target.read_bytes()).hexdigest()
   report['counters']={k:qmp.request('qom-get',{'path':'/machine/ans','property':k}) for k in
    ['mmio-read-count','mmio-write-count','submission-count','rejected-count','crypto-rejected-count']}
   require(report['counters']['crypto-rejected-count']==1,'crypto reject observed')
   require(report['counters']['rejected-count']>=2,'duplicate and crypto refusals observed')
   expected=bytearray(65536);expected[3*4096:4*4096]=PATTERN
   expected[7*4096:9*4096]=PATTERN*2
   require(backing.read_bytes()==expected,'only intended block persisted; negatives unchanged')
   report['backing_sha256_at_flush']=sha(backing)
   if mode=='write':
    require(p.poll() is None,'owned child alive before deliberate process crash')
    require(Path(f'/proc/{p.pid}/stat').read_text().rsplit(')',1)[1].split()[19]==report['start_ticks'],'owned child identity')
    p.kill();report['stop_method']='owned-process-crash-after-flush'
   else:qmp.request('quit');report['stop_method']='qmp-quit'
   p.wait(timeout=8);report['qemu_returncode']=p.returncode
   require(p.returncode==(-9 if mode=='write' else 0),'expected own child exit')
   report['passed']=True
 except Exception as e:
  report['error']=str(e)
 finally:
  if p and p.poll() is None:
   p.terminate()
   try:p.wait(timeout=5)
   except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
  if p:report['child_reaped']=p.poll() is not None
  if p:report['qemu_returncode']=p.returncode
  report['elapsed_seconds']=time.monotonic()-start
  report['inputs_unchanged']=report['inputs_before']=={k:sha(v) for k,v in assets.items()}
  report['backing_sha256_after_close']=sha(backing)
  (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 require(report['passed'],report.get('error','CPU gate failed'))
 return report

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--binary',type=Path,required=True)
 ap.add_argument('--components',type=Path,required=True);ap.add_argument('--output-dir',type=Path,required=True)
 a=ap.parse_args();out=a.output_dir.resolve();out.mkdir(exist_ok=False)
 assets={k:a.components.resolve()/k for k in board.ASSETS}
 layout=board.expected_layout({k:p.read_bytes() for k,p in assets.items()})
 for lo,size in layout['regions'].values():require(DMA+0x20000<=lo or BASE>=lo+size,'owned buffers outside boot assets')
 backing=out/'persistent.raw';backing.write_bytes(bytes(65536))
 rows=[]
 for mode in ['write','recovery','readonly']:rows.append(run_case(a.binary.resolve(),assets,out/mode,backing,mode))
 require(rows[0]['pid']!=rows[1]['pid'],'fresh process recovery')
 require(rows[0]['backing_sha256_after_close']==rows[1]['backing_sha256_after_close']==rows[2]['backing_sha256_after_close'],'stable backend recovery')
 (out/'report.json').write_text(json.dumps({'passed':True,'cases':[{'mode':r['mode'],'pid':r['pid'],'passed':r['passed']} for r in rows],
  'backing_sha256':sha(backing),'cpu_readback_sha256':hashlib.sha256(PATTERN*2).hexdigest(),
  'native_nvme_flush_process_crash_recovery':True,'ios_driver_qualified':False,
  'coastguard_security_qualified':False,'sep_encryption_qualified':False,'host_power_loss_qualified':False},indent=2)+'\n')
 print('PASS: actual ARM64 CPU, backend write/flush/crash/reopen/read, read-only/invalid DMA/crypto refusal, tag reuse/CQ wrap')
if __name__=='__main__':main()
