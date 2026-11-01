"""Локальное окно. Сеть и браузер работают в отдельном ограниченном процессе."""
import os
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from .bundle import verify
from .process import run_capture


class App:
    def __init__(self, root):
        self.root = root
        root.title('SealSnap: веб-снимки')
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
        ttk.Label(body, text='Сохранить веб-снимок', font=('Segoe UI', 18, 'bold')).pack(anchor='w')
        ttk.Label(body, text='Пассивный режим: без JavaScript, входа в аккаунты и iframe.\n'
                  'Сложные сайты могут отображаться частично. Высота снимка до 6000 пикселей.').pack(anchor='w', pady=(7, 15))
        ttk.Label(body, text='Адрес страницы (http:// или https://)').pack(anchor='w')
        ttk.Entry(body, textvariable=self.url).pack(fill='x', pady=(4, 10))
        row = ttk.Frame(body)
        row.pack(fill='x')
        ttk.Entry(row, textvariable=self.output).pack(side='left', fill='x', expand=True)
        ttk.Button(row, text='Папка…', command=self.choose_output).pack(side='right', padx=(8, 0))
        actions = ttk.Frame(body)
        actions.pack(fill='x', pady=12)
        self.capture_button = ttk.Button(actions, text='Сохранить снимок', command=self.capture)
        self.capture_button.pack(side='left')
        ttk.Button(actions, text='Отменить', command=self.cancel.set).pack(side='left', padx=8)
        ttk.Button(actions, text='Открыть папку', command=self.open_folder).pack(side='right')
        ttk.Separator(body).pack(fill='x', pady=5)
        ttk.Label(body, text='Известный отпечаток манифеста (необязательно; храните отдельно от пакета)').pack(anchor='w', pady=(5, 4))
        ttk.Entry(body, textvariable=self.anchor).pack(fill='x')
        self.verify_button = ttk.Button(body, text='Выбрать и проверить пакет…', command=self.check)
        self.verify_button.pack(anchor='w', pady=8)
        self.log = tk.Text(body, height=10, wrap='word', font=('Segoe UI', 10), state='disabled')
        self.log.pack(fill='both', expand=True)
        self.write('Готово. Снимки хранятся только на этом компьютере.\n'
                   'Хэши проверяют совпадение файлов; время и авторство они не удостоверяют.')
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
        self.write('Сбор страницы. Лимит операции 70 секунд; окно можно закрыть для отмены.')
        self.launch(lambda: run_capture(url, output, self.cancel))

    def check(self):
        folder = filedialog.askdirectory(title='Папка с manifest.json')
        if folder:
            anchor = self.anchor.get().strip() or None
            self.launch(lambda: verify(folder, anchor))

    def open_folder(self):
        if self.last_folder and Path(self.last_folder).is_dir():
            os.startfile(self.last_folder)

    def close(self):
        self.closing = True
        self.cancel.set()
        self.write('Завершение собственного рабочего процесса…')

    def poll(self):
        try:
            kind, value = self.queue.get_nowait()
            if kind == 'error':
                self.write('Операция не завершена: ' + value)
            else:
                self.last_folder = value['path']
                anchored = value['external_fingerprint_checked']
                self.write('Пакет сохранён и проверен.' if 'mode' in value else 'Файлы совпадают с манифестом.')
                self.log.configure(state='normal')
                self.log.insert('end', '\n\n' + value['path'] + '\n\nОтпечаток манифеста:\n' +
                    value['manifest_sha256'] + '\n\n' + ('Отпечаток сверен с указанным вами значением.' if anchored else
                    'Внешний отпечаток не задан: замену всех файлов вместе с манифестом эта проверка не выявляет.') +
                    '\nВремя взято с компьютера. Подлинность и полнота сайта не удостоверены.')
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
