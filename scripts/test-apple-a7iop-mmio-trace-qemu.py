#!/usr/bin/env python3
"""Optional tracing gate using the existing owned-ROM SEP transport oracle.

Only owned instructions execute. No firmware driver, DCP progress or iOS boot
is claimed. The same harmless register/frame operations run with tracing on/off.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

p=argparse.ArgumentParser()
p.add_argument('--worktree',type=Path,required=True)
p.add_argument('--binary',type=Path,required=True)
p.add_argument('--components',type=Path,required=True)
p.add_argument('--out',type=Path,required=True)
a=p.parse_args()
a.out.mkdir(parents=True,exist_ok=False)
spec=importlib.util.spec_from_file_location('owned_transport',a.worktree/'scripts/test-apple-modern-sep-transport-qemu.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
base_rom=m.ROM
class ROM(base_rom):
    def read32(self,address,register=0):
        if address==m.mailbox.IDLE_STATUS:
            # Preserve the reset CPU_CTRL value; this must not start the peer.
            self.write32(m.mailbox.SEP_WRAP+0x44,0)
        return super().read32(address,register)
m.ROM=ROM
m.FINAL={**m.FINAL,'wrapper-mmio-write-count':1}
events=['apple_a7iop_wrapper_read','apple_a7iop_wrapper_write',
        'apple_a7iop_mailbox_read','apple_a7iop_mailbox_write']
reports=[]
real_popen=subprocess.Popen
for arm,enabled in [('default-off',False),('enabled',True)]:
    out=a.out/arm;out.mkdir()
    event_file=out/'events.txt';event_file.write_text('\n'.join(events)+'\n' if enabled else '')
    effective=[]
    def launch(argv,*args,**kwargs):
        command=[*argv,'-trace',f'events={event_file.resolve()},file={(out/"trace.log").resolve()}']
        effective.append(command)
        return real_popen(command,*args,**kwargs)
    m.subprocess.Popen=launch
    try:
        assert m.run(a.binary.resolve(),a.components.resolve(),out)==0
    finally:
        m.subprocess.Popen=real_popen
    (out/'effective-argv.json').write_text(json.dumps(effective,indent=2)+'\n')
    r=json.loads((out/'report.json').read_text())
    assert r['passed'] and len(r['passes'])==2
    lines=(out/'trace.log').read_text().splitlines() if (out/'trace.log').exists() else []
    counts={event:sum(event+' ' in line for line in lines) for event in events}
    if enabled:
        assert all(counts.values()),counts
        assert any('wrapper_read' in ln and 'read @0x8000 size=4' in ln for ln in lines)
        assert any('wrapper_write' in ln and 'write @0x44 size=4 value=0x0' in ln for ln in lines)
    else:
        assert not any(counts.values()),counts
    reports.append({'arm':arm,'trace_enabled':enabled,'transport_passed':True,'reset_iterations':2,'event_counts':counts,'owned_rom_sha256':r['rom_sha256'],'observed':[v['observed'] for v in r['passes']]})
assert reports[0]['owned_rom_sha256']==reports[1]['owned_rom_sha256']
assert reports[0]['observed']==reports[1]['observed']
(a.out/'result.json').write_text(json.dumps({'passed':True,'firmware_executed':False,'v6_owned_cpu_trace_qualified':True,'v4_runtime_trace_qualified':False,'scope':'Handled MMIO witness and default-off oracle; transport/IRQ replies unchanged through two resets, not DCP/iOS progress','arms':reports},indent=2)+'\n')
print('trace gate passes: all four handled V6 access types visible; default-off oracle silent; transport results match')
