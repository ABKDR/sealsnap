"""Local window. Network and browser work runs in a separate restricted process."""
import os
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog
from .bundle import verify
from .process import run_capture

TEXTS = {
    'en': {
        'title': 'SealSnap: web snapshots',
        'heading': 'Save a web snapshot',
        'intro': 'Passive mode: no JavaScript, no account sign-in and no iframes.\n'
                 'Complex sites may look incomplete. Snapshot height is up to 6000 pixels.',
        'url': 'Page address (http:// or https://)',
        'folder': 'Folder…',
        'save': 'Save snapshot',
        'cancel': 'Cancel',
        'open': 'Open folder',
        'anchor': 'Known manifest fingerprint (optional; keep it apart from the package)',
        'verify': 'Choose and verify a package…',
        'ready': 'Ready. Snapshots are stored only on this computer.\n'
                 'Hashes show that files match; they do not certify time or authorship.',
        'capturing': 'Capturing the page. The operation is limited to 70 seconds; close the window to cancel.',
        'choose': 'Folder with manifest.json',
        'closing': 'Stopping the worker process…',
        'failed': 'Operation not completed: ',
        'saved': 'Package saved and verified.',
        'matches': 'Files match the manifest.',
        'fingerprint': 'Manifest fingerprint:',
        'anchored': 'The fingerprint matches the value you entered.',
        'not_anchored': 'No external fingerprint was given: this check does not detect replacement '
                        'of all files together with the manifest.',
        'caveat': 'Time is taken from this computer. The authenticity and completeness of the site '
                  'are not certified.',
    },
    'ru': {
        'title': 'SealSnap: веб-снимки',
        'heading': 'Сохранить веб-снимок',
        'intro': 'Пассивный режим: без JavaScript, входа в аккаунты и iframe.\n'
                 'Сложные сайты могут отображаться частично. Высота снимка до 6000 пикселей.',
        'url': 'Адрес страницы (http:// или https://)',
        'folder': 'Папка…',
        'save': 'Сохранить снимок',
        'cancel': 'Отменить',
        'open': 'Открыть папку',
        'anchor': 'Известный отпечаток манифеста (необязательно; храните отдельно от пакета)',
        'verify': 'Выбрать и проверить пакет…',
        'ready': 'Готово. Снимки хранятся только на этом компьютере.\n'
                 'Хэши проверяют совпадение файлов; время и авторство они не удостоверяют.',
        'capturing': 'Сбор страницы. Лимит операции 70 секунд; окно можно закрыть для отмены.',
        'choose': 'Папка с manifest.json',
        'closing': 'Завершение собственного рабочего процесса…',
        'failed': 'Операция не завершена: ',
        'saved': 'Пакет сохранён и проверен.',
        'matches': 'Файлы совпадают с манифестом.',
        'fingerprint': 'Отпечаток манифеста:',
        'anchored': 'Отпечаток сверен с указанным вами значением.',
        'not_anchored': 'Внешний отпечаток не задан: замену всех файлов вместе с манифестом эта '
                        'проверка не выявляет.',
        'caveat': 'Время взято с компьютера. Подлинность и полнота сайта не удостоверены.',
    },
}


def language():
    """SEALSNAP_LANG=en|ru wins; otherwise Russian for a Russian Windows interface, else English."""
    choice = os.environ.get('SEALSNAP_LANG', '').strip().lower()
    if choice in TEXTS:
        return choice
    try:
        import ctypes
        if (ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3FF) == 0x19:
            return 'ru'
    except (AttributeError, OSError):
        pass
    return 'en'


class App:
    def __init__(self, root, lang=None):
        self.root = root
        self.t = t = TEXTS[lang or language()]
        root.title(t['title'])
        root.geometry('820x570')
        root.minsize(680, 490)
        self.queue = queue.Queue()
        self.cancel = threading.Event()
        self.thread = None
        self.closing = False
        self.last_folder = None
        self.url = tk.StringVar(value='https://example.com')
        self.output = tk.StringVar(value=str(Path(__file__).resolve().parent.parent / 'captures'))
        self.anchor = tk.StringVar()
        body = ttk.Frame(root, padding=20)
        body.pack(fill='both', expand=True)
        ttk.Label(body, text=t['heading'], font=('Segoe UI', 18, 'bold')).pack(anchor='w')
        ttk.Label(body, text=t['intro']).pack(anchor='w', pady=(7, 15))
        ttk.Label(body, text=t['url']).pack(anchor='w')
        ttk.Entry(body, textvariable=self.url).pack(fill='x', pady=(4, 10))
        row = ttk.Frame(body)
        row.pack(fill='x')
        ttk.Entry(row, textvariable=self.output).pack(side='left', fill='x', expand=True)
        ttk.Button(row, text=t['folder'], command=self.choose_output).pack(side='right', padx=(8, 0))
        actions = ttk.Frame(body)
        actions.pack(fill='x', pady=12)
        self.capture_button = ttk.Button(actions, text=t['save'], command=self.capture)
        self.capture_button.pack(side='left')
        ttk.Button(actions, text=t['cancel'], command=self.cancel.set).pack(side='left', padx=8)
        ttk.Button(actions, text=t['open'], command=self.open_folder).pack(side='right')
        ttk.Separator(body).pack(fill='x', pady=5)
        ttk.Label(body, text=t['anchor']).pack(anchor='w', pady=(5, 4))
        ttk.Entry(body, textvariable=self.anchor).pack(fill='x')
        self.verify_button = ttk.Button(body, text=t['verify'], command=self.check)
        self.verify_button.pack(anchor='w', pady=8)
        self.log = tk.Text(body, height=10, wrap='word', font=('Segoe UI', 10), state='disabled')
        self.log.pack(fill='both', expand=True)
        self.write(t['ready'])
        root.protocol('WM_DELETE_WINDOW', self.close)
        root.after(100, self.poll)

    def write(self, text):
        self.log.configure(state='normal')
        self.log.delete('1.0', 'end')
        self.log.insert('end', text)
        self.log.configure(state='disabled')

    def choose_output(self):
        folder = filedialog.askdirectory()
        if folder:
            self.output.set(folder)

    def launch(self, function):
        if self.thread and self.thread.is_alive():
            return
        self.cancel.clear()
        self.capture_button.configure(state='disabled')
        self.verify_button.configure(state='disabled')
        def work():
            try:
                self.queue.put(('result', function()))
            except Exception as e:
                self.queue.put(('error', str(e)))
        self.thread = threading.Thread(target=work, daemon=False)
        self.thread.start()

    def capture(self):
        url, output = self.url.get().strip(), self.output.get()
        self.write(self.t['capturing'])
        self.launch(lambda: run_capture(url, output, self.cancel))

    def check(self):
        folder = filedialog.askdirectory(title=self.t['choose'])
        if folder:
            anchor = self.anchor.get().strip() or None
            self.launch(lambda: verify(folder, anchor))

    def open_folder(self):
        if self.last_folder and Path(self.last_folder).is_dir():
            os.startfile(self.last_folder)

    def close(self):
        self.closing = True
        self.cancel.set()
        self.write(self.t['closing'])

    def poll(self):
        t = self.t
        try:
            kind, value = self.queue.get_nowait()
            if kind == 'error':
                self.write(t['failed'] + value)
            else:
                self.last_folder = value['path']
                anchored = value['external_fingerprint_checked']
                self.write(t['saved'] if 'mode' in value else t['matches'])
                self.log.configure(state='normal')
                self.log.insert('end', '\n\n' + value['path'] + '\n\n' + t['fingerprint'] + '\n' +
                    value['manifest_sha256'] + '\n\n' + (t['anchored'] if anchored else t['not_anchored']) +
                    '\n' + t['caveat'])
                self.log.configure(state='disabled')
            self.capture_button.configure(state='normal')
            self.verify_button.configure(state='normal')
        except queue.Empty:
            pass
        if self.closing and (self.thread is None or not self.thread.is_alive()):
            self.root.destroy()
        else:
            self.root.after(100, self.poll)


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()
