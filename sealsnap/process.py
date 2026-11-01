"""Рабочий процесс в Windows Job: память ограничена, закрытие уничтожает только своё дерево."""
import ctypes
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import subprocess
import sys
import sysconfig
import tempfile
from .network import SnapshotError


def worker_command():
    # Windows venv python.exe is a redirector: its child can start before Job.attach.
    # Run the actual interpreter directly, with only our project/venv import paths.
    base = Path(getattr(sys, '_base_executable', sys.executable)).resolve().with_name('pythonw.exe')
    # The windowed binary also avoids an OS-created console host before attachment.
    # stdin/stdout/stderr are explicitly inherited pipes, so the protocol remains available.
    if not base.is_file():
        raise SnapshotError('BASE_PYTHON_MISSING')
    paths = list(dict.fromkeys([str(Path(__file__).resolve().parent.parent),
        sysconfig.get_path('purelib'), sysconfig.get_path('platlib')]))
    bootstrap = ('import sys,runpy;sys.path[:0]=' + repr(paths) +
                 ';runpy.run_module("sealsnap.worker",run_name="__main__")')
    return [str(base), '-I', '-S', '-B', '-c', bootstrap]


class Job:
    def __init__(self):
        if os.name != 'nt':
            raise SnapshotError('WINDOWS_REQUIRED')
        class Basic(ctypes.Structure):
            _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64),
                ('flags', w.DWORD), ('min_ws', ctypes.c_size_t), ('max_ws', ctypes.c_size_t),
                ('active', w.DWORD), ('affinity', ctypes.c_size_t), ('priority', w.DWORD), ('scheduling', w.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(n, ctypes.c_uint64) for n in ('read_ops', 'write_ops', 'other_ops', 'read_bytes', 'write_bytes', 'other_bytes')]
        class Extended(ctypes.Structure):
            _fields_ = [('basic', Basic), ('io', IO), ('process_memory', ctypes.c_size_t),
                ('job_memory', ctypes.c_size_t), ('peak_process', ctypes.c_size_t), ('peak_job', ctypes.c_size_t)]
        self.k = ctypes.WinDLL('kernel32', use_last_error=True)
        self.k.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
        self.k.CreateJobObjectW.restype = w.HANDLE
        self.k.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
        self.k.SetInformationJobObject.restype = w.BOOL
        self.k.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        self.k.AssignProcessToJobObject.restype = w.BOOL
        self.k.CloseHandle.argtypes = [w.HANDLE]
        self.k.CloseHandle.restype = w.BOOL
        self.handle = self.k.CreateJobObjectW(None, None)
        if not self.handle:
            raise SnapshotError('JOB_CREATE_FAILED')
        limits = Extended()
        limits.basic.flags = 0x2000 | 0x200  # KILL_ON_JOB_CLOSE | JOB_MEMORY
        limits.job_memory = 1536 * 1024 * 1024
        if not self.k.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise SnapshotError('JOB_LIMIT_FAILED')

    def attach(self, process):
        if not self.k.AssignProcessToJobObject(self.handle, w.HANDLE(int(process._handle))):
            raise SnapshotError('JOB_ATTACH_FAILED')

    def close(self):
        if self.handle:
            self.k.CloseHandle(self.handle)
            self.handle = None


def parse_worker_output(out):
    try:
        result = json.loads(out)
    except (ValueError, UnicodeError, RecursionError):
        raise SnapshotError('WORKER_FAILED') from None
    if type(result) is not dict:
        raise SnapshotError('WORKER_FAILED')
    return result


def run_capture(url, output, cancel=None):
    root = Path(__file__).resolve().parent.parent
    job = Job()
    proc = None
    # This directory owns both Playwright's profile and intermediary output.
    with tempfile.TemporaryDirectory(prefix='_proba_sealsnap_worker_') as temp:
        try:
            env = {k: v for k, v in os.environ.items() if k.upper() in {
                'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATH', 'PATHEXT', 'PROGRAMFILES',
                'PROGRAMFILES(X86)', 'LOCALAPPDATA', 'USERPROFILE', 'APPDATA'}}
            env.update(TEMP=temp, TMP=temp, PYTHONUTF8='1', PYTHONDONTWRITEBYTECODE='1')
            # The worker waits for stdin BEFORE importing capture/Playwright or spawning children.
            proc = subprocess.Popen(worker_command(),
                cwd=root, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW)
            job.attach(proc)
            payload = json.dumps({'url': url, 'output': str(output)}, ensure_ascii=False).encode('utf-8')
            import time
            start = time.monotonic()
            sent = False
            while True:
                if cancel is not None and cancel.is_set():
                    raise SnapshotError('CANCELLED')
                if time.monotonic() - start > 70:
                    raise SnapshotError('WORKER_TIMEOUT')
                try:
                    out, err = proc.communicate(input=payload if not sent else None, timeout=0.2)
                    break
                except subprocess.TimeoutExpired:
                    sent = True
            if len(out) > 32768:
                raise SnapshotError('WORKER_OUTPUT_LIMIT')
            result = parse_worker_output(out)
            if proc.returncode != 0 or result.get('ok') is not True:
                raise SnapshotError(str(result.get('error', 'WORKER_FAILED'))[:200])
            return result
        finally:
            job.close()
            if proc is not None:
                if proc.poll() is None:
                    proc.kill()
                proc.communicate(timeout=10)
