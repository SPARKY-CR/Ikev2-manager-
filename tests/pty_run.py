#!/usr/bin/env python3
"""Run a command in a pseudo-terminal and type lines into it whenever it is waiting for input.
usage: pty_run.py CMD [ARGS...] -- LINE [LINE...]      prints the output, exits with the command's status"""
import os
import pty
import select
import sys
import time


def run(cmd, lines, idle=0.2, timeout=60):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(cmd[0], cmd, os.environ)
    out, queue, deadline, status = b"", list(lines), time.time() + timeout, 1
    while True:
        r, _, _ = select.select([fd], [], [], idle)
        if r:
            try:
                data = os.read(fd, 65536)
            except OSError:
                data = b""
            if not data:
                break
            out += data
        elif queue:
            os.write(fd, (queue.pop(0) + "\n").encode())
        elif time.time() > deadline:
            os.kill(pid, 9)
            break
        else:
            wpid, st = os.waitpid(pid, os.WNOHANG)
            if wpid:
                status = os.waitstatus_to_exitcode(st)
                return out, status
    try:
        _, st = os.waitpid(pid, 0)
        status = os.waitstatus_to_exitcode(st)
    except ChildProcessError:
        pass
    return out, status


if __name__ == "__main__":
    i = sys.argv.index("--")
    out, status = run(sys.argv[1:i], sys.argv[i + 1:])
    sys.stdout.write(out.decode(errors="replace").replace("\r", ""))
    sys.exit(status)
