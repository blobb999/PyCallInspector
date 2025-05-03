# -*- coding: utf-8-sig -*-
import sys
import os
import runpy
import threading
import subprocess
import signal
import atexit
import tkinter as tk
import tempfile
import time
from tkinter import ttk, filedialog, messagebox

# Global set to store called functions in monitor subprocess
defined_functions = set()

# --- Stop Flag Mechanism ---
_main_thread_stop_requested = False
class StopMonitorRequested(Exception):
    pass

# Profiling function
def profile_func(frame, event, arg):
    global _main_thread_stop_requested
    if _main_thread_stop_requested:
        raise StopMonitorRequested()
    if event != 'call':
        return
    try:
        code = frame.f_code
        filename = code.co_filename
        if filename.endswith('.py') and os.path.isfile(filename):
            normalized = filename.replace('\\', '/').lower()
            if 'lib' not in normalized and 'site-packages' not in normalized:
                defined_functions.add((code.co_name, filename, code.co_firstlineno))
    except Exception:
        pass
    return profile_func

# Print summary of collected functions
def print_summary():
    if not defined_functions:
        print("[Monitor] Keine Funktionen gesammelt.")
        return
    print("\n🧠 Aufgerufene Funktionen (aus eigenen .py-Dateien):")
    cwd = os.getcwd()
    for funcname, path, line in sorted(defined_functions, key=lambda x: (x[1], x[2])):
        short = os.path.relpath(path, cwd)
        print(f" - {funcname}()  @ {short}:{line}")
    sys.stdout.flush()

# Signal handler (Unix)
def signal_handler(signum, frame):
    global _main_thread_stop_requested
    if not _main_thread_stop_requested:
        print(f"[Monitor] Signal {signum} erhalten, Stop-Flag gesetzt.")
        sys.stdout.flush()
        _main_thread_stop_requested = True

# File watcher for Windows
def stop_file_watcher(stop_file_path):
    global _main_thread_stop_requested
    while not _main_thread_stop_requested:
        if os.path.exists(stop_file_path):
            print(f"[Monitor] Stop-Datei {stop_file_path} gefunden. Flag gesetzt.")
            _main_thread_stop_requested = True
            try:
                os.remove(stop_file_path)
            except OSError:
                pass
            break
        time.sleep(0.5)

# Main wrapper to run target under profiler
def wrapper_main(target_script):
    # Ensure imports from script's directory
    script_dir = os.path.dirname(os.path.abspath(target_script))
    if script_dir and script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    try:
        os.chdir(script_dir)
    except Exception:
        pass

    # Setup Windows stop file watcher
    stop_file = None
    if sys.platform == 'win32':
        stop_file = os.environ.get('MONITOR_STOP_FILE')
        if stop_file:
            threading.Thread(target=stop_file_watcher, args=(stop_file,), daemon=True).start()
        else:
            print("[Monitor] MONITOR_STOP_FILE nicht gesetzt.")

    # Prepare arguments and summary
    sys.argv = [target_script] + sys.argv[3:]
    atexit.register(print_summary)

    # Setup signal handlers for Unix
    if sys.platform != 'win32':
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, signal_handler)

    # Start profiling
    sys.setprofile(profile_func)

    try:
        print(f"[Monitor] Starte {target_script} mit args: {sys.argv}")
        runpy.run_path(target_script, run_name='__main__')
        print("[Monitor] Ziel-Skript normal beendet.")
    except StopMonitorRequested:
        print("[Monitor] Stop-Anfrage empfangen, Unterbrechung erfolgreich.")
    except SystemExit as e:
        if getattr(e, 'code', 0) != 0:
            print(f"[Monitor] Ziel-Skript mit Code {e.code} beendet.")
    except Exception as e:
        print(f"[Monitor] Fehler beim Ausführen: {e}")
    finally:
        sys.setprofile(None)
        print("[Monitor] Profiling gestoppt.")

# GUI: start monitoring subprocess
def start_monitor(script_path, text_widget, start_button, stop_button):
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'
    stop_file = None
    cmd = [sys.executable, '-u', __file__, 'monitor', script_path]
    if sys.platform == 'win32':
        stop_file = os.path.join(tempfile.gettempdir(), f"monitor_{os.getpid()}.stop")
        env['MONITOR_STOP_FILE'] = stop_file
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        text=True,
        encoding='utf-8',
        env=env
    )
    start_button.config(state='disabled')
    stop_button.config(state='normal')

    def reader():
        for line in process.stdout:
            if text_widget.winfo_exists():
                text_widget.insert(tk.END, line)
                text_widget.see(tk.END)
        process.stdout.close()
        process.wait()
        start_button.config(state='normal')
        stop_button.config(state='disabled')
        if stop_file and os.path.exists(stop_file):
            try:
                os.remove(stop_file)
            except OSError:
                pass

    threading.Thread(target=reader, daemon=True).start()
    return process, stop_file

# GUI: stop monitoring subprocess
def stop_monitor(process, stop_file=None):
    if process.poll() is None:
        if sys.platform == 'win32' and stop_file:
            with open(stop_file, 'w'):
                pass
        elif sys.platform != 'win32':
            process.send_signal(signal.SIGINT)
        else:
            process.terminate()

# Tkinter App class
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PyCallInspector")
        self.geometry("800x600")
        self.process = None
        self.stop_file = None
        self.create_widgets()

    def create_widgets(self):
        frm = ttk.Frame(self)
        frm.pack(padx=10, pady=10, fill='x')
        ttk.Label(frm, text='Script Path:').grid(row=0, column=0, sticky='w')
        self.path_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.path_var, width=80).grid(row=0, column=1, sticky='ew')
        ttk.Button(frm, text='Browse...', command=self.browse_file).grid(row=0, column=2, padx=5)
        self.btn_start = ttk.Button(frm, text='Start', command=self.on_start)
        self.btn_start.grid(row=1, column=1, pady=5, sticky='e')
        self.btn_stop = ttk.Button(frm, text='Stop', command=self.on_stop, state='disabled')
        self.btn_stop.grid(row=1, column=2, pady=5, sticky='w')
        self.text = tk.Text(self, wrap='none')
        self.text.pack(fill='both', expand=True, padx=10, pady=10)
        scroll = ttk.Scrollbar(self, orient='vertical', command=self.text.yview)
        self.text['yscrollcommand'] = scroll.set
        scroll.pack(side='right', fill='y')

    def browse_file(self):
        path = filedialog.askopenfilename(filetypes=[('Python Files', '*.py')])
        if path:
            self.path_var.set(path)

    def on_start(self):
        path = self.path_var.get()
        if not path or not os.path.isfile(path):
            messagebox.showerror("Error", "Ungültige Datei.")
            return
        if self.process and self.process.poll() is None:
            stop_monitor(self.process, self.stop_file)
        if self.stop_file and os.path.exists(self.stop_file):
            os.remove(self.stop_file)
        self.text.delete(1.0, tk.END)
        self.process, self.stop_file = start_monitor(path, self.text, self.btn_start, self.btn_stop)

    def on_stop(self):
        stop_monitor(self.process, self.stop_file)

    def on_closing(self):
        if self.process and self.process.poll() is None:
            stop_monitor(self.process, self.stop_file)
        if self.stop_file and os.path.exists(self.stop_file):
            os.remove(self.stop_file)
        self.destroy()

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'monitor':
        if len(sys.argv) < 3:
            print("Usage: monitor <script.py>")
        else:
            wrapper_main(sys.argv[2])
    else:
        app = App()
        app.protocol("WM_DELETE_WINDOW", app.on_closing)
        app.mainloop()
