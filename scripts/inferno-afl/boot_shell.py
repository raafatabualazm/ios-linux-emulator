#!/usr/bin/env python3
"""Boot the prepared Inferno Bash ramdisk with isolated writable disks."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

import validate_runtime as rt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    rt.add_path_arguments(parser)
    parser.add_argument('--image', type=Path)
    args = parser.parse_args()
    rt.configure_paths(args, parser)
    image = args.image or rt.LAB / 'ios_shell.img'
    if not image.is_file():
        parser.error(f'Prepare the separate shell image first: {image}')
    with tempfile.TemporaryDirectory(prefix='inferno-shell-') as directory:
        work = Path(directory)
        rt.prepare_disks(work)
        argv = rt.arguments(work)
        argv[argv.index('-initrd') + 1] = str(image.resolve())
        argv[argv.index('-serial') + 1] = 'mon:stdio'
        index = argv.index('-d')
        del argv[index:index+6]
        environment = os.environ.copy()
        for name in ['__AFL_SHM_ID', '__AFL_PERSISTENT', 'AFL_HARNESS_SCOPE']:
            environment.pop(name, None)
        print('Wait for bash-5.0#. Ctrl-A then x quits QEMU.', flush=True)
        result = subprocess.run(argv, env=environment)
        raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
