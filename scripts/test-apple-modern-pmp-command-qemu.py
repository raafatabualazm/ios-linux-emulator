#!/usr/bin/env python3
"""Actual ARM64 command commit/ack, default-off and reset checks.

Only the owned ROM executes. Protocol expectations are from the retained AP and
PMP firmware disassembly, profile Q; no power readiness or quota grant is implied.
"""
import argparse, importlib.util, json, struct, subprocess, tempfile, time
from pathlib import Path
spec=importlib.util.spec_from_file_location('pmp_command_helpers',Path(__file__).with_name('test-apple-modern-ans-qemu.py'))
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
DASH=0x3003c0000;UPDATE=0x3003d0000
class ROM(h.mb.ROM):
 def __init__(self,enabled):super().__init__();self.enabled=enabled
 def check(self,label,slot,value,meta=False):
  self.read64(DASH+slot*16+int(meta)*8,23);self.trace(label,value,register=23)
 def build(self):
  self.mov(20,h.RESULT);self.mov(0,h.mb.NORMAL_SP);self.emit(0x9100001f)
  self.check('ack_initial',448,0)
  self.write64(UPDATE+433*8,0);self.check('no_ack_before_commit',448,0)
  self.write64(UPDATE+432*8,0x1002)
  self.check('commit_seq2',448,2 if self.enabled else 0)
  self.check('ack_new_data',448,2 if self.enabled else 0,meta=True)
  self.check('online_remains_zero',1,0);self.check('quota_remains_zero',440,0)
  self.write64(UPDATE+432*8,0xf000)
  self.check('seq_zero_does_not_publish',448,2 if self.enabled else 0)
  self.write64(UPDATE+432*8,0xefff)
  self.check('ack_low12_only',448,0xfff if self.enabled else 0)
  self.mov(0,h.DONE);self.trace('completion',h.DONE);self.branch(len(self.words))
  return struct.pack('<'+'I'*len(self.words),*self.words)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--binary',type=Path,required=True)
 ap.add_argument('--components',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
 a=ap.parse_args();out=a.output.resolve();out.mkdir(exist_ok=False)
 assets={k:a.components.resolve()/k for k in h.board.ASSETS};before={k:h.sha(p) for k,p in assets.items()}
 reports=[]
 for enabled in [False,True]:
  folder=out/('quiet' if enabled else 'off');folder.mkdir()
  rom=ROM(enabled);raw=rom.build();(folder/'owned.rom').write_bytes(raw);(folder/'zero.bin').write_bytes(bytes(4096))
  machine='apple-modern,'+','.join(k+'='+str(assets[v]) for k,v in zip(('bootkc','sptm','txm','dtree','tc'),h.board.ASSETS))+',prepare-only=on,modern-pmp-ptd=on'
  argv=[str(a.binary.resolve()),'-M',machine,'-m','8G','-smp','1','-nodefaults','-display','none','-serial','none','-monitor','none',
   '-global','apple-modern-pmp-ptd.command-responder='+('on' if enabled else 'off'),
   '-device',f'loader,file={folder}/owned.rom,addr={h.BASE},cpu-num=0,force-raw=true',
   '-device',f'loader,file={folder}/zero.bin,addr={h.RESULT},force-raw=true','-S','-qmp','stdio']
  row={'passed':False,'enabled':enabled,'argv':argv,'passes':[]};p=None;start=time.monotonic()
  def guard():h.require(time.monotonic()-start<20,'PMP CPU gate deadline');return 20-(time.monotonic()-start)
  try:
   with (folder/'qemu.log').open('xb') as log:
    p=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,bufsize=0,start_new_session=True)
    q=h.h.QMP(None,guard,p);row['pid']=p.pid
    h.require(q.request('qom-get',{'path':'/machine/pmp-ptd','property':'command-responder'}) is enabled,'actual profile')
    try:q.request('qom-set',{'path':'/machine/pmp-ptd','property':'command-responder','value':not enabled})
    except RuntimeError as e:row['immutable_profile']=str(e)
    else:raise RuntimeError('runtime responder profile mutation admitted')
    for iteration in range(2):
     q.request('cont')
     with tempfile.TemporaryDirectory(prefix='pmp-command-cpu-') as tmp:
      target=Path(tmp)/'results'
      while True:
       guard();time.sleep(.05);q.request('stop');q.request('pmemsave',{'val':h.RESULT,'size':4096,'filename':str(target)})
       data=target.read_bytes();values=struct.unpack_from('<'+'Q'*len(rom.expected),data)
       if values[-1]==h.DONE:break
       q.request('cont')
      h.require(list(values)==list(rom.expected.values()),'CPU command/ack contract '+str(dict(zip(rom.expected,values))))
      (folder/f'pass{iteration}.bin').write_bytes(data)
     counts={k:q.request('qom-get',{'path':'/machine/pmp-ptd','property':k}) for k in ['command-count','ack-count','command-word0','command-word1']}
     h.require(counts=={'command-count':3,'ack-count':2 if enabled else 0,'command-word0':0xefff,'command-word1':0},'exact device diagnostics')
     row['passes'].append({'cpu_checks':dict(zip(rom.expected,values)),'counters':counts})
     if iteration==0:
      q.request('system_reset');h.require(q.request('query-status')['running'] is False,'reset stopped')
      h.require(q.request('qom-get',{'path':'/machine/pmp-ptd','property':'ack-count'})==0,'reset ack counter')
    q.request('quit');h.require(p.wait(timeout=5)==0,'clean exit');row['passed']=True
  finally:
   if p and p.poll() is None:p.terminate();p.wait(timeout=5)
   row['child_reaped']=p is not None and p.poll() is not None;row['seconds']=time.monotonic()-start
   (folder/'report.json').write_text(json.dumps(row,indent=2)+'\n')
  reports.append(row)
 h.require(before=={k:h.sha(p) for k,p in assets.items()},'firmware inputs unchanged')
 (out/'report.json').write_text(json.dumps({'passed':True,'runs':reports,'binary_sha256':h.sha(a.binary),'inputs':before,'firmware_executed':False,'power_ready_qualified':False,'quota_policy_qualified':False},indent=2)+'\n')
 print('PASS: ARM64 PMP command commit/sequence/new-data/default-off/reset; no power-ready or quota claims')
if __name__=='__main__':main()
