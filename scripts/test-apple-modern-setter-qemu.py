#!/usr/bin/env python3
"""Actual stopped-QEMU regression for independent display/voltage string options.

The old pin is the defect oracle, never executes firmware. The fixed pin must
preserve both properties in either CLI order; three actual QMP sets for each
property must refuse because the machine is initialized and preserve its values.
A clean QMP quit tests teardown. Duplicate CLI syntax is not claimed to prove
repeated pre-initialization setters (QEMU may collapse duplicate keys).
"""
import argparse, hashlib, importlib.util, json, os, subprocess, time
from pathlib import Path
spec=importlib.util.spec_from_file_location('transport',Path(__file__).with_name('test-apple-modern-sep-transport-qemu.py'))
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
p=argparse.ArgumentParser();p.add_argument('--binary',required=True,type=Path);p.add_argument('--old-binary',required=True,type=Path);p.add_argument('--components',required=True,type=Path);p.add_argument('--dtree',required=True,type=Path);p.add_argument('--out',required=True,type=Path);a=p.parse_args()
for field in ['binary','old_binary','components','dtree','out']:setattr(a,field,getattr(a,field).resolve())
a.out.mkdir(exist_ok=False,parents=True)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def available():return int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))
assets=[a.components/name for name in t.board.ASSETS];assets[3]=a.dtree
inputs=[a.binary,a.old_binary,*assets];before={str(path):digest(path) for path in inputs}
def refused(qmp,prop,value):
 qmp.guard();qmp.sequence+=1;identifier=qmp.sequence
 qmp.send(json.dumps({'execute':'qom-set','id':identifier,'arguments':{'path':'/machine','property':prop,'value':value}}).encode()+b'\n',time.monotonic()+3)
 deadline=time.monotonic()+3
 while time.monotonic()<deadline:
  reply=qmp.receive(deadline)
  if 'event' in reply:qmp.events.append(reply['event']);continue
  assert reply.get('id')==identifier
  assert 'error' in reply and 'return' not in reply,reply
  assert 'fixed after initialization' in reply['error']['desc'],reply
  return reply['error']
 raise AssertionError('QMP refusal deadline')
def arm(name,binary,extra,expect_defect=False):
 out=a.out/name;out.mkdir();logpath=out/'emulator.log';process=qmp=None;start=time.monotonic();startavail=available();minimum=startavail
 machine='apple-modern,'+','.join(n+'='+str(path) for n,path in zip(['bootkc','sptm','txm','dtree','tc'],assets))+',prepare-only=on,'+extra
 argv=[str(binary),'-M',machine,'-m','8G','-smp','1','-nodefaults','-display','none','-serial','none','-monitor','none','-S','-qmp','stdio']
 report={'name':name,'passed':False,'firmware_executed':False,'guest_instructions_executed':False,'argv':argv,'environment':{'MALLOC_PERTURB_':'170','G_SLICE':'always-malloc'},'mem_available_start_kb':startavail,'refusals':[]}
 try:
  assert startavail>=7000000
  with logpath.open('xb') as log:
   process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,bufsize=0,env=dict(os.environ,MALLOC_PERTURB_='170',G_SLICE='always-malloc'))
   def guard():
    nonlocal minimum
    minimum=min(minimum,available());assert minimum>=900000
    left=20-(time.monotonic()-start);assert left>0 and logpath.stat().st_size<(1<<20)
    return left
   qmp=t.QMP(None,guard,process)
   assert not qmp.request('query-status')['running']
   props={'disp0-probe':'dcp-mapper','pmgr-voltage-states':'j700'}
   for prop,value in props.items():assert qmp.request('qom-get',{'path':'/machine','property':prop})==value
   for prop in props:
    for value in ['off','dcp-chain' if prop=='disp0-probe' else 'j700','off']:
     report['refusals'].append({'property':prop,'value':value,'error':refused(qmp,prop,value)})
     for check,value2 in props.items():assert qmp.request('qom-get',{'path':'/machine','property':check})==value2
   qmp.request('quit');assert process.wait(timeout=5)==0;process=None
   assert not expect_defect,'Old pin did not demonstrate the defect'
   report['passed']=True
 except Exception as error:
  report['error']=str(error)
  if expect_defect:
   if process and process.poll() is None:
    try:process.wait(timeout=2)
    except subprocess.TimeoutExpired:pass
   code=process.poll() if process else None
   report['defect_exit']=code
   # An actual initialization exit is required; a timeout is not a defect oracle.
   report['defect_diagnostic']=logpath.read_text(errors='replace')
   report['passed']=code is not None and code!=0 and "unknown disp0-probe arm 'j700'" in report['defect_diagnostic']
 finally:
  if process:
   if process.poll() is None:process.kill()
   process.wait(timeout=5)
  if qmp:qmp.close()
  report['mem_available_min_kb']=minimum;report['seconds']=time.monotonic()-start
  (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
 return report
arms=[arm('fixed-display-first',a.binary,'disp0-probe=dcp-mapper,pmgr-voltage-states=j700'),arm('fixed-voltage-first',a.binary,'pmgr-voltage-states=j700,disp0-probe=dcp-mapper'),arm('old-display-first',a.old_binary,'disp0-probe=dcp-mapper,pmgr-voltage-states=j700',True)]
after={str(path):digest(path) for path in inputs};r={'passed':all(v['passed'] for v in arms) and before==after,'inputs_unchanged':before==after,'inputs_before':before,'inputs_after':after,'arms':arms};(a.out/'result.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'passed':r['passed'],'arms':[(v['name'],v['passed'],v.get('error')) for v in arms]}));raise SystemExit(0 if r['passed'] else 1)
