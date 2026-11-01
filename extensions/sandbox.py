"""Sandbox launcher for one extension process (run as `python -I -B extensions/sandbox.py <spec.json>`).

A fresh, single-threaded process sets up the sandbox and then exec()s the extension, so no thread of the
engine is involved:

  * user namespace (unprivileged; the extension keeps its own uid, so it has no capabilities after exec),
  * network namespace without interfaces, unless the manifest asks for network and the Admin allowed it,
  * mount namespace: the appliance's data, configuration and log directories are covered by empty
    read-only tmpfs mounts, /tmp is private, and the extension's own directory is mounted read-only at
    /tmp/extension (its working directory),
  * no new privileges, resource limits (address space, CPU time, open files, no core dumps, no file writes),
    lower CPU priority, an empty environment.

If any step fails the launcher exits with status 97 and the extension does not run (fail closed).
"""
import ctypes
import json
import os
import resource
import sys

MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC = 1, 2, 4, 8
MS_REMOUNT, MS_BIND, MS_REC, MS_PRIVATE = 32, 4096, 16384, 1 << 18
PR_SET_NO_NEW_PRIVS = 38
SANDBOX_FAILED = 97


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def _mount(libc, source, target, fstype, flags, data=None):
    enc = lambda v: v.encode() if isinstance(v, str) else v  # noqa: E731
    if libc.mount(enc(source), enc(target), enc(fstype), ctypes.c_ulong(flags), enc(data)) != 0:
        err = ctypes.get_errno()
        raise OSError(err, f'mount {target}: {os.strerror(err)}')


def _write(path, text):
    with open(path, 'w') as f:
        f.write(text)


def enter(spec):
    """Everything up to the exec; raises OSError when the sandbox cannot be built."""
    libc = _libc()
    uid, gid = os.getuid(), os.getgid()
    flags = os.CLONE_NEWUSER | os.CLONE_NEWNS
    if not spec.get('network'):
        flags |= os.CLONE_NEWNET
    os.unshare(flags)
    _write('/proc/self/setgroups', 'deny')
    _write('/proc/self/uid_map', f'{uid} {uid} 1')        # same uid inside: no capabilities after exec
    _write('/proc/self/gid_map', f'{gid} {gid} 1')
    _mount(libc, None, '/', None, MS_REC | MS_PRIVATE)
    # opened before anything is covered, so the extension directory may live anywhere (even under /tmp)
    src = os.open(spec['dir'], os.O_RDONLY | os.O_DIRECTORY)
    # nosec B108 (below): this /tmp is a new tmpfs in the extension's own mount namespace, not the shared /tmp
    _mount(libc, 'tmpfs', '/tmp', 'tmpfs', MS_NOSUID | MS_NODEV, 'size=16m,mode=0755')  # nosec B108
    os.mkdir('/tmp/extension')  # nosec B108
    _mount(libc, f'/proc/self/fd/{src}', '/tmp/extension', None, MS_BIND | MS_REC)  # nosec B108
    os.close(src)
    _mount(libc, None, '/tmp/extension', None, MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NODEV)  # nosec B108
    for hidden in spec.get('hide', []):
        if os.path.isdir(hidden):
            _mount(libc, 'tmpfs', hidden, 'tmpfs', MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, 'size=4k,mode=0555')
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'no_new_privs')
    mem = int(spec.get('memory_mb', 256)) * 1024 * 1024
    for res, value in ((resource.RLIMIT_AS, mem), (resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 0),
                       (resource.RLIMIT_NOFILE, 32), (resource.RLIMIT_CPU, int(spec.get('cpu_seconds', 86400)))):
        resource.setrlimit(res, (value, value))
    os.nice(10)
    os.chdir('/tmp/extension')  # nosec B108


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    try:
        with open(argv[0], encoding='utf-8') as f:
            spec = json.load(f)
        enter(spec)
    except (OSError, ValueError, KeyError, IndexError) as exc:
        sys.stderr.write(f'sandbox: {exc}\n')
        sys.stderr.flush()
        os._exit(SANDBOX_FAILED)
    env = {'PYTHONPATH': spec['sdk'], 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUNBUFFERED': '1',
           'SENTINEL_EXTENSION': spec['name'], 'LANG': 'C.UTF-8'}
    # -S: no site-packages (the standard library and the SDK only); -B: no bytecode files
    os.execve(spec['python'], [spec['python'], '-B', '-S', spec['entry']], env)


if __name__ == '__main__':
    main()
