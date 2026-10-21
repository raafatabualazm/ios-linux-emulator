#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Black-box tests for the SEP lab machine, using synthetic AArch64 only.

Usage:
  python tests/functional/test_apple_sep_lab.py \
    --qemu build-sep-lab/qemu-system-aarch64 --output results.json

No Apple firmware is required. These tests do not establish sepOS compatibility.
"""
import argparse
import json
import pathlib
import socket
import struct
import subprocess
import tempfile
import time

AP_REGIONS = [(0x282600000, 0x88000), (0x282050000, 0x60000)]
# MOV X0,#0x1000; MOV W1,#42; STR W1,[X0]; MOV X2,#1,LSL#32;
# STR W1,[X2]; B .
PROBE = struct.pack("<6I", 0xD2820000, 0x52800541, 0xB9000001,
                    0xD2C00022, 0xB9000041, 0x14000000)

class VM:
    def __init__(self, qemu, root, image, suffix="", extra=None):
        self.root = root
        self.trace = root/("trace"+suffix+".jsonl")
        self.stderr = (root/("stderr"+suffix+".log")).open("w+")
        self.sockpath = root/("qmp"+suffix+".sock")
        command = [
            qemu, "-machine", "apple-sep-lab,trace-file="+str(self.trace),
            "-accel", "tcg,thread=single", "-m", "16M", "-bios", str(image),
            "-nodefaults", "-display", "none", "-serial", "none",
            "-monitor", "none", "-S", "-qmp",
            "unix:"+str(self.sockpath)+",server=on,wait=off",
        ]
        command += extra or []
        self.process = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                                        stderr=self.stderr)
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        deadline = time.monotonic()+15
        while True:
            if self.process.poll() is not None:
                self.stderr.seek(0)
                raise AssertionError("QEMU exited at startup: "+self.stderr.read())
            try:
                self.socket.connect(str(self.sockpath))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic()>deadline:
                    raise TimeoutError("QMP startup")
                time.sleep(0.02)
        self.socket.settimeout(5)
        self.stream = self.socket.makefile("rwb", buffering=0)
        greeting = json.loads(self.stream.readline())
        assert "QMP" in greeting, greeting
        self.sequence = 0
        self.command("qmp_capabilities")
    def command(self, command, arguments=None):
        self.sequence += 1
        request = {"execute":command,"id":self.sequence}
        if arguments is not None: request["arguments"] = arguments
        self.stream.write(json.dumps(request).encode()+b"\n")
        while True:
            line = self.stream.readline()
            if not line: raise RuntimeError("QMP closed")
            response = json.loads(line)
            if response.get("id")==self.sequence:
                if "error" in response: raise AssertionError(response)
                return response.get("return")
    def events(self):
        if not self.trace.exists(): return []
        return [json.loads(line) for line in self.trace.read_text().splitlines()]
    def physical_readl(self, address):
        self.command("qom-set",{
            "path":"/machine","property":"x-ap-probe","value":f"0x{address:x}"})
        # This exercises host AP address space, not a guest-visible success.
    def wait_stopped(self):
        deadline = time.monotonic()+5
        while time.monotonic()<deadline:
            status = self.command("query-status")
            if status["status"]=="internal-error":
                return status
            time.sleep(0.02)
        raise AssertionError("Expected explicit internal-error stop")
    def close(self):
        try:
            if self.process.poll() is None: self.command("quit")
        finally:
            self.stream.close()
            self.socket.close()
            try: self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait()
            self.stderr.close()

def reject(qemu, image, needle, *extra):
    run = subprocess.run([
        qemu, "-machine", "apple-sep-lab", "-accel", "tcg",
        "-nodefaults", "-display", "none", "-serial", "none",
        "-monitor", "none", "-bios", str(image), *extra
    ],capture_output=True,text=True,timeout=10)
    assert run.returncode != 0, "Invalid image accepted"
    assert needle in run.stderr, run.stderr
    return {"returncode":run.returncode,"diagnostic":run.stderr.strip()}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--qemu",required=True)
    parser.add_argument("--output")
    args = parser.parse_args()
    qemu = str(pathlib.Path(args.qemu).resolve())
    result = {"machine":"apple-sep-lab","firmware":"synthetic AArch64 only",
              "tests":[],"target_compatibility_verified":False}
    listing = subprocess.run([qemu,"-machine","help"],capture_output=True,
                             text=True,check=True,timeout=10)
    assert "apple-sep-lab" in listing.stdout
    with tempfile.TemporaryDirectory(prefix="sep-lab-test-") as td:
        root = pathlib.Path(td)
        image = root/"probe.bin"; image.write_bytes(PROBE)
        vm = VM(qemu,root,image)
        try:
            vm.command("cont")
            status = vm.wait_stopped()
            memory = vm.command("human-monitor-command",{
                "command-line":"xp /1wx 0x1000"})
            assert "0x0000002a" in memory, memory
            faults = [e for e in vm.events() if e["event"]=="unsupported-mmio"]
            assert len(faults)==1, faults
            assert faults[0]["domain"]=="sep-private"
            assert faults[0]["address"]=="0x100000000"
            assert faults[0]["size"]==4 and faults[0]["write"] is True
            assert "value" not in faults[0]
            result["tests"].append({"name":"executes AArch64 and stops on unknown private MMIO",
                                    "status":status,"memory":memory.strip(),
                                    "trace":faults[0]})
            generation = max(e["generation"] for e in vm.events())
            vm.command("system_reset")
            assert max(e["generation"] for e in vm.events()) > generation
            result["tests"].append({"name":"reset advances generation","passed":True})
            try:
                vm.command("migrate",{"uri":"file:"+str(root/"migration.bin")})
                raise AssertionError("Migration was incorrectly accepted")
            except AssertionError as error:
                assert "migration/snapshot semantics are not implemented" in str(error), error
            result["tests"].append({"name":"unimplemented migration is rejected",
                                    "passed":True})
        finally:
            vm.close()

        idle = root/"idle.bin"
        idle.write_bytes(struct.pack("<I",0x14000000))
        for i,(base,size) in enumerate(AP_REGIONS):
            for j,address in enumerate([base,base+size-4]):
                vm = VM(qemu,root,idle,f"-ap{i}-{j}")
                try:
                    vm.command("cont")
                    vm.physical_readl(address)
                    vm.wait_stopped()
                    faults = [e for e in vm.events() if e["event"]=="unsupported-mmio"]
                    assert len(faults)==1 and faults[0]["domain"]=="ap", faults
                    assert int(faults[0]["address"],16)==address
                    result["tests"].append({
                        "name":f"AP region {i} boundary {j} fails explicitly",
                        "trace":faults[0]})
                finally: vm.close()

        for name,data,needle in [
            ("empty",b"","image must be nonempty"),
            ("unaligned",b"\0"*7,"4-byte aligned"),
            ("im4p",b"\x30\x1e\x16\x04IM4P"+b"\0"*24,"not IMG4/IM4P"),
            ("macho",bytes.fromhex("cffaedfe")+b"\0"*28,"requires its own loader"),
        ]:
            path=root/(name+".bin");path.write_bytes(data)
            result["tests"].append({"name":"reject "+name,**reject(qemu,path,needle)})
        result["tests"].append({
            "name":"reject out-of-image entry",
            **reject(qemu,image,"contain the aligned entry point",
                     "-machine","apple-sep-lab,entry=0x1000")})
    result["passed"] = True
    result["test_count"] = len(result["tests"])
    if args.output:
        pathlib.Path(args.output).write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))

if __name__=="__main__":
    main()
