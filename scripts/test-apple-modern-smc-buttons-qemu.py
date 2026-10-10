#!/usr/bin/env python3
"""QMP F3/F4/F5 -> unchanged legacy button peer -> SMC packet + real AIC IRQ.

Only an owned ROM executes. Duplicate down/up events must not enqueue a second
notification. Active-low bVDN/bVUP/bHLD reads and IRQ delivery repeat after reset.
This qualifies the declared host route, not Apple's semantic event consumption.
No display/console is supplied: the legacy handler accepts unbound QMP events.
"""
import argparse, importlib.util, json, struct, subprocess, tempfile, time
from pathlib import Path
spec = importlib.util.spec_from_file_location('smc_owned', Path(__file__).with_name('test-apple-modern-smc-qemu.py'))
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)
m, b, t = s.m, s.b, s.t
CASES = [('f3', 3, 'bVDN', True), ('f3', 3, 'bVDN', False),
         ('f4', 2, 'bVUP', True), ('f4', 2, 'bVUP', False),
         ('f5', 1, 'bHLD', True), ('f5', 1, 'bHLD', False)]
LINE = 584  # served ADT interrupt index 2: AP_NONEMPTY
class ROM(s.ROM):
 def finish(self):
  self.set('HCR_EL2', (1 << 31) | (1 << 34) | (1 << 4))
  self.mov(21, 0); self.mov(22, 0)
  self.write32(m.AIC_BASE + m.GLBCFG, 1)
  for i, (qcode, button, key, down) in enumerate(CASES):
   self.unmask(LINE)
   self.mov(0, i + 1); self.store(0, 0x400)
   self.emit(0xd50342ff); self.await_count(i + 1); self.emit(0xd503425f)
   self.trace('button_irq_count_' + str(i), i + 1, register=21)
   self.trace('button_irq_event_' + str(i), m.EVENT_IRQ | LINE, register=22)
   notification = 0x18 | ((int(down) | (button << 8) | (1 << 16) | (0x72 << 24)) << 32)
   self.receive('button_packet_' + str(i), notification, 32)
   self.send((int.from_bytes(key.encode(), 'big') << 32) | (4 << 16) | ((0x50 + i) << 8) | 0x10, 32)
   self.receive('button_key_' + str(i), (int(not down) << 32) | (4 << 16) | ((0x50 + i) << 8), 32)
   self.mov(0, i + 1); self.store(0, 0x408)
  super().finish()
 def build(self):
  raw = bytearray(super().build())
  irq = m.ROM(); irq.read32(m.AIC_BASE + m.EVENT, 22)
  irq.emit(0x910006b5); irq.emit(0xd69f03e0)
  code = b''.join(struct.pack('<I', word) for word in irq.words)
  raw[0x4280:0x4280 + len(code)] = code
  assert len(self.expected) * 8 < 0x400
  return bytes(raw)
def run(a):
 out=a.out;rom=ROM(False);content=rom.build();rp=out/'owned.rom';rp.write_bytes(content);zp=out/'zero.bin';zp.write_bytes(bytes(0x510));logp=out/'qemu.log'
 assets=[a.components/n for n in b.ASSETS];assets[3]=a.dtree
 before={str(p):s.digest(p) for p in [a.binary,*assets]}
 machine='apple-modern,'+','.join(n+'='+str(p) for n,p in zip(['bootkc','sptm','txm','dtree','tc'],assets))+',prepare-only=on,modern-aic=on,aic-record-irq-config=on,adt-compat-restore=smc,modern-smc=on,modern-smc-buttons=on'
 argv=[str(a.binary),'-M',machine,'-m','8G','-smp','1','-nodefaults','-display','none','-serial','none','-monitor','none','-device',f'loader,file={rp},addr={m.BASE},cpu-num=0,force-raw=true','-device',f'loader,file={zp},addr={m.SCRATCH},force-raw=true','-S','-qmp','stdio']
 report={'passed':False,'firmware_executed':False,'apple_event_consumption_qualified':False,'argv':argv,'inputs_before':before,'owned_rom_sha256':s.digest(rp),'passes':[],'mem_available_start_kb':s.available()};process=qmp=None;start=time.monotonic();minimum=report['mem_available_start_kb']
 try:
  assert minimum>=7000000
  with tempfile.TemporaryDirectory() as tmp,logp.open('xb') as log:
   process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,bufsize=0,preexec_fn=s.child_limits)
   def guard():
    nonlocal minimum
    minimum=min(minimum,s.available());assert minimum>=900000
    left=60-(time.monotonic()-start);assert left>0 and logp.stat().st_size<(1<<20);return left
   qmp=t.QMP(None,guard,process);dp=Path(tmp)/'dump'
   def wait_marker(offset,value):
    deadline=time.monotonic()+5
    while True:
     guard();qmp.request('stop');qmp.request('pmemsave',{'val':m.SCRATCH,'size':0x510,'filename':str(dp)});raw=dp.read_bytes()
     assert raw[0x500:0x510]==bytes(16), 'Unexpected owned-ROM exception'
     if struct.unpack_from('<Q',raw,offset)[0]==value:return raw
     assert time.monotonic()<deadline, 'Owned marker deadline'
     qmp.request('cont');time.sleep(.02)
   for iteration in range(2):
    if iteration:qmp.request('system_reset')
    regs=b.parse_registers(qmp.request('human-monitor-command',{'command-line':'info registers'}));assert regs['PC']==m.BASE and regs['PSTATE']&15==9
    qmp.request('pmemsave',{'val':m.BASE,'size':len(content),'filename':str(dp)});assert dp.read_bytes()==content
    qmp.request('pmemsave',{'val':m.SCRATCH,'size':0x510,'filename':str(dp)});assert dp.read_bytes()==bytes(0x510)
    qmp.request('cont');events=[]
    for i,(qcode,button,key,down) in enumerate(CASES):
     wait_marker(0x400,i+1);qmp.request('cont')
     event={'type':'key','data':{'down':down,'key':{'type':'qcode','data':qcode}}}
     # One real transition plus a duplicate must still yield exactly one packet.
     qmp.request('input-send-event',{'events':[event,event]})
     wait_marker(0x408,i+1);events.append({'qcode':qcode,'down':down,'duplicate':True})
    raw=wait_marker((len(rom.expected)-1)*8,s.DONE)
    observed={k:struct.unpack_from('<Q',raw,i*8)[0] for i,k in enumerate(rom.expected)}
    assert observed==rom.expected,(observed,rom.expected)
    report['passes'].append({'iteration':iteration,'qmp_events':events,'observed':observed})
   qmp.request('quit');assert process.wait(timeout=5)==0;process=None;report['passed']=True
 except Exception as error:report['error']=str(error)
 finally:
  if process:process.kill();process.wait(timeout=5)
  if qmp:qmp.close()
  after={str(p):s.digest(p) for p in [a.binary,*assets]};report['inputs_after']=after;report['inputs_unchanged']=before==after;report['passed'] &= before==after
  report['mem_available_min_kb']=minimum;report['seconds']=time.monotonic()-start
  (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
 return report
p=argparse.ArgumentParser();p.add_argument('--binary',required=True,type=Path);p.add_argument('--components',required=True,type=Path);p.add_argument('--dtree',required=True,type=Path);p.add_argument('--out',required=True,type=Path);a=p.parse_args()
for name in ['binary','components','dtree','out']:setattr(a,name,getattr(a,name).resolve())
a.out.mkdir(exist_ok=False,parents=True);r=run(a);print(json.dumps({'passed':r['passed'],'error':r.get('error')}));raise SystemExit(0 if r['passed'] else 1)
