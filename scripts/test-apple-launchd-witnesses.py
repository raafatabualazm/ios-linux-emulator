#!/usr/bin/env python3
"""Negative oracles for distinctions that would overstate SpringBoard progress."""
import importlib.util
import pathlib
import tempfile

script = pathlib.Path(__file__).with_name('analyse-apple-launchd-witnesses.py')
spec = importlib.util.spec_from_file_location('witnesses', script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
prefix = 'com.apple.xpc.launchd|1970-01-01 00:10:00.000000 '
with tempfile.TemporaryDirectory() as tmp:
    path = pathlib.Path(tmp) / 'serial.log'
    path.write_text(
        prefix + '(user/501/com.apple.SpringBoard [5]) <Notice>: xpcproxy spawned with pid 5\r\r\n' +
        prefix + '(user/501/com.apple.SpringBoard [5]) <Notice>: service state: xpcproxy\r\n' +
        prefix + '(system/com.apple.oracle [6]) <Notice>: internal event: INIT, code = 111\n' +
        prefix + '(system/com.apple.oracle [6]) <Notice>: exited due to exit(78)\n' +
        prefix + '(system/com.apple.actual [7]) <Notice>: service state: running\r\n' +
        prefix + '(com.apple.App) <Notice>: service will always use xpcproxy, elision was disabled by boot-arg\n' +
        prefix + '(user/501/com.apple.App [8]) <Notice>: launchd(proxyless) spawned with pid 8\n' +
        prefix + '(system) <Notice>: entering bootstrap mode\n' +
        prefix + '(user/501) <Notice>: exiting bootstrap mode\r\r\n' +
        prefix + '(user/501) <Notice>: exiting ondemand mode\n' +
        prefix + '(user/501/com.apple.other) <Notice>: exiting bootstrap mode\n' +
        prefix + '(system/com.apple.other) <Error>: requestor = SpringBoard[99]\n')
    result = module.read(path)
    sb = result['jobs']['com.apple.SpringBoard']
    assert sb['spawns'][0]['pid'] == 5 and sb['states'] == ['xpcproxy']
    assert not sb['running_witnesses'] and not sb['init_witnesses']
    oracle = result['jobs']['com.apple.oracle']
    assert oracle['init_witnesses'][0]['code'] == 111 and not oracle['running_witnesses']
    assert result['unique_running_jobs'] == 1
    assert result['jobs']['com.apple.App']['spawns'][0]['proxy'] == 'launchd(proxyless)'
    assert result['jobs']['com.apple.App']['elision_disabled_by_boot_arg']
    assert len(sb['spawns']) == 1  # requestor text on another label is not a SpringBoard witness
    assert [(m['domain'], m['event']) for m in result['domain_milestones']] == [
        ('system', 'bootstrap_enter'), ('user/501', 'bootstrap_exit'), ('user/501', 'ondemand_exit')]
print('PASS: proxy carrier, failed INIT, CR lines, exact running, proxyless literal, unrelated requestor, domain milestones')
