"""Safe subprocess helpers for executing repository scripts with validation.

Provides a minimal validation layer so code that spawns local helper scripts
ensures the target is a repo-local script or the Python interpreter and avoids
accidental shell interpolation.
"""
import os
import sys
import shutil
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


class SubprocessSafetyError(RuntimeError):
    pass


def _is_repo_path(path: str) -> bool:
    try:
        p = Path(path).resolve()
    except Exception:
        return False
    try:
        return REPO_ROOT in p.parents or p == REPO_ROOT
    except Exception:
        return False


def safe_popen(args, cwd=None, env=None, stdout=None, stderr=None):
    if not args:
        raise SubprocessSafetyError('empty args')
    exe = args[0]
    # allow system python interpreter explicitly
    python_execs = {sys.executable, shutil.which('python3') or '', shutil.which('python') or ''}
    if exe in python_execs:
        return subprocess.Popen(args, cwd=cwd, env=env, stdout=stdout, stderr=stderr)

    # if argument is a script path, ensure it's inside the repo
    if os.path.isabs(exe):
        if not _is_repo_path(exe):
            raise SubprocessSafetyError(f'executable not inside repo: {exe}')
        if not os.path.exists(exe):
            raise SubprocessSafetyError(f'script not found: {exe}')
        return subprocess.Popen(args, cwd=cwd, env=env, stdout=stdout, stderr=stderr)

    # resolve relative paths against cwd or repo root
    candidate = Path(cwd or REPO_ROOT) / exe
    if candidate.exists() and _is_repo_path(str(candidate)):
        return subprocess.Popen([str(candidate)] + args[1:], cwd=cwd, env=env, stdout=stdout, stderr=stderr)

    # fallback: try locating in PATH but require explicit confirmation
    which = shutil.which(exe)
    if which:
        # only allow common trusted binaries (git, curl) explicitly
        trusted = {'git', 'curl', 'sh', 'bash'}
        if os.path.basename(which) in trusted:
            return subprocess.Popen([which] + args[1:], cwd=cwd, env=env, stdout=stdout, stderr=stderr)
    raise SubprocessSafetyError(f'untrusted executable: {exe}')


def safe_run(args, cwd=None, env=None, timeout=None, check=False):
    p = safe_popen(args, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate(timeout=timeout)
    if check and p.returncode != 0:
        raise subprocess.CalledProcessError(p.returncode, args, output=out, stderr=err)
    return subprocess.CompletedProcess(args=args, returncode=p.returncode, stdout=out, stderr=err)

# expose commonly used subprocess constants so other modules don't need to import subprocess
PIPE = subprocess.PIPE
DEVNULL = subprocess.DEVNULL
