"""Живой GUI-прогон: запускать отдельно, он обращается к example.com.

Кнопки вызываются через Tcl/Tk invoke; выбор папки заменяется своим тестовым
путём. Сеть, рабочий процесс, отрисовка и проверка пакета не подменяются.
Это не тест физического указателя мыши или системного диалога выбора папки.

Отчёт пишется в JSON-файл: путь берётся из переменной окружения
SEALSNAP_GUI_SMOKE_REPORT, по умолчанию sealsnap-gui-smoke.json во временной
папке системы.
"""
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import tkinter as tk
import traceback
from unittest.mock import patch

from sealsnap.gui import App
from sealsnap.bundle import verify

REPORT = Path(os.environ.get('SEALSNAP_GUI_SMOKE_REPORT')
              or Path(tempfile.gettempdir()) / 'sealsnap-gui-smoke.json')


def main():
    results = []
    report = REPORT
    report.write_text(json.dumps({'status': 'RUNNING'}), encoding='utf-8')
    with tempfile.TemporaryDirectory(prefix='_proba_sealsnap_gui_') as tmp:
        root = tk.Tk()
        app = App(root)
        def await_idle(limit=75):
            until = time.monotonic() + limit
            while time.monotonic() < until:
                root.update()
                if not app.capture_button.instate(['disabled']):
                    return app.log.get('1.0', 'end').strip()
                time.sleep(0.02)
            raise AssertionError('GUI_TIMEOUT')

        def record(name, text):
            results.append({'case': name, 'result': text})
            print(name + ': ' + text, flush=True)

        try:
            root.update()
            app.output.set(tmp)
            app.url.set('https://example.com/')
            app.capture_button.invoke()
            text = await_idle()
            assert text.startswith('Пакет сохранён и проверен.'), text
            folder = Path(app.last_folder)
            receipt = verify(folder)['manifest_sha256']
            record('real-capture', text)

            with patch('sealsnap.gui.filedialog.askdirectory', return_value=str(folder)):
                app.anchor.set(receipt)
                app.verify_button.invoke()
                text = await_idle()
                assert 'Отпечаток сверен с указанным вами значением.' in text, text
                record('verify-known-receipt', text)

                (folder/'source.html.txt').write_bytes(b'deliberate test modification')
                app.verify_button.invoke()
                text = await_idle()
                assert 'FILE_DIGEST_MISMATCH:source.html.txt' in text, text
                record('red-tampered-package', text)

            app.url.set('http://127.0.0.1/')
            app.capture_button.invoke()
            text = await_idle()
            assert 'NON_PUBLIC_ADDRESS' in text, text
            record('red-local-address', text)

            def descendants(widget):
                for child in widget.winfo_children():
                    yield child
                    yield from descendants(child)
            cancel_button = next(w for w in descendants(root)
                if w.winfo_class() == 'TButton' and w.cget('text') == 'Отменить')
            app.url.set('https://example.com/')
            app.capture_button.invoke()
            cancel_button.invoke()
            text = await_idle()
            assert 'CANCELLED' in text, text
            record('cancel-button', text)

            # Closing is delivered through the actual registered WM_DELETE_WINDOW
            # Tcl callback while a real worker is active, not through a fake worker.
            app.url.set('https://example.com/')
            app.capture_button.invoke()
            assert app.thread is not None and app.thread.is_alive()
            close_callback = root.protocol('WM_DELETE_WINDOW')
            root.tk.call(close_callback)
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                try:
                    root.update()
                    if not root.winfo_exists():
                        break
                except tk.TclError:
                    break
                time.sleep(.02)
            assert not app.thread.is_alive(), 'WORKER_THREAD_REMAINED'
            record('close-during-capture', 'WM_DELETE_WINDOW callback completed; worker thread stopped')
        finally:
            app.cancel.set()
            if app.thread:
                app.thread.join(timeout=12)
            try:
                root.destroy()
            except tk.TclError:
                pass
    assert not Path(tmp).exists(), 'TEMP_REMAINED'
    assert not [t for t in threading.enumerate() if t is not threading.main_thread()], 'THREADS_REMAINED'
    report.write_text(json.dumps({'status': 'PASS', 'method': 'Tcl/Tk button invoke and registered close callback',
        'results': results, 'temporary_directory_removed': True, 'remaining_threads': 0},
        ensure_ascii=False, indent=2), encoding='utf-8')
    print('GUI_SMOKE_PASS ' + str(report), flush=True)


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        REPORT.write_text(json.dumps(
            {'status': 'FAIL', 'traceback': traceback.format_exc()},
            ensure_ascii=False, indent=2), encoding='utf-8')
        raise
