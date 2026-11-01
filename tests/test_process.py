import ctypes
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from sealsnap.process import Job, parse_worker_output, run_capture
from sealsnap.network import SnapshotError


@unittest.skipUnless(os.name=='nt','Windows Job test')
class ProcessTests(unittest.TestCase):
    def test_delayed_attach_contains_actual_interpreter(self):
        # A venv redirector may create the real interpreter before Job.attach.
        # Delay attachment to reproduce that scheduling window deterministically.
        original = Job.attach
        def delayed(job, process):
            time.sleep(0.2)
            original(job, process)
            k=ctypes.WinDLL('kernel32',use_last_error=True)
            from ctypes import wintypes as w
            class Entry(ctypes.Structure):
                _fields_=[('dwSize',w.DWORD),('cntUsage',w.DWORD),('pid',w.DWORD),
                    ('heap',ctypes.c_size_t),('module',w.DWORD),('threads',w.DWORD),
                    ('parent',w.DWORD),('priority',w.LONG),('flags',w.DWORD),('exe',w.WCHAR*260)]
            k.CreateToolhelp32Snapshot.argtypes=[w.DWORD,w.DWORD]
            k.CreateToolhelp32Snapshot.restype=w.HANDLE
            k.Process32FirstW.argtypes=[w.HANDLE,ctypes.POINTER(Entry)]
            k.Process32NextW.argtypes=[w.HANDLE,ctypes.POINTER(Entry)]
            k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];k.OpenProcess.restype=w.HANDLE
            k.IsProcessInJob.argtypes=[w.HANDLE,w.HANDLE,ctypes.POINTER(w.BOOL)]
            k.CloseHandle.argtypes=[w.HANDLE]
            snap=k.CreateToolhelp32Snapshot(2,0)
            self.assertNotEqual(snap,ctypes.c_void_p(-1).value)
            pairs=[]
            try:
                e=Entry();e.dwSize=ctypes.sizeof(e)
                more=k.Process32FirstW(snap,ctypes.byref(e))
                self.assertTrue(more)
                while more:
                    pairs.append((e.pid,e.parent))
                    more=k.Process32NextW(snap,ctypes.byref(e))
            finally:k.CloseHandle(snap)
            descendants={process.pid}
            for _ in range(len(pairs)):
                added={pid for pid,parent in pairs if parent in descendants}
                if added <= descendants:break
                descendants |= added
            for pid in descendants:
                handle=k.OpenProcess(0x1000,False,pid)
                self.assertTrue(handle)
                try:
                    member=w.BOOL()
                    self.assertTrue(k.IsProcessInJob(handle,job.handle,ctypes.byref(member)))
                    self.assertTrue(member.value,f'process {pid} escaped the memory-limited Job')
                finally:k.CloseHandle(handle)
        with tempfile.TemporaryDirectory(prefix='_proba_sealsnap_attach_') as tmp:
            with patch.object(Job,'attach',delayed), self.assertRaisesRegex(SnapshotError,'NON_PUBLIC_ADDRESS'):
                run_capture('http://127.0.0.1/',tmp)

    def test_worker_output_parsing(self):
        for out in (b'[' * 16000, b'{"a":' * 5000, b'[]', b'"x"', b'', b'{"ok": tru'):
            with self.subTest(out=out[:12]), self.assertRaisesRegex(SnapshotError, 'WORKER_FAILED'):
                parse_worker_output(out)
        self.assertEqual(parse_worker_output(b'{"ok": true}'), {'ok': True})

    def test_cancel_before_network(self):
        cancel=threading.Event();cancel.set()
        with tempfile.TemporaryDirectory(prefix='_proba_sealsnap_cancel_') as tmp:
            with self.assertRaisesRegex(SnapshotError,'CANCELLED'):
                run_capture('https://example.com',tmp,cancel)
            self.assertEqual(os.listdir(tmp),[])

    def test_job_closes_child_tree(self):
        job=Job()
        code=('import sys,subprocess,time;sys.stdin.readline();'
              'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"],'
              'creationflags=0x08000000);print(p.pid,flush=True);time.sleep(60)')
        p=subprocess.Popen([sys.executable,'-B','-c',code],stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            job.attach(p)
            p.stdin.write(b'go\n');p.stdin.flush()
            child=int(p.stdout.readline())
            k=ctypes.WinDLL('kernel32',use_last_error=True)
            k.OpenProcess.argtypes=[ctypes.c_uint32,ctypes.c_int,ctypes.c_uint32]
            k.OpenProcess.restype=ctypes.c_void_p
            k.WaitForSingleObject.argtypes=[ctypes.c_void_p,ctypes.c_uint32]
            k.CloseHandle.argtypes=[ctypes.c_void_p]
            h=k.OpenProcess(0x100000,False,child)
            self.assertTrue(h)
            try:
                self.assertEqual(k.WaitForSingleObject(h,0),258)
                job.close()
                self.assertEqual(k.WaitForSingleObject(h,5000),0)
                p.wait(timeout=5)
            finally:k.CloseHandle(h)
        finally:
            job.close()
            if p.poll() is None:p.kill()
            p.communicate(timeout=5)
