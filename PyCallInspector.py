# -*- coding: utf-8-sig -*-
import sys
import os
import runpy
import threading
import subprocess
import signal
import atexit
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import ast
import tempfile
import time

# Global sets and lists to store called functions and call hierarchy
defined_functions = set()
call_stack = []
call_tree = []

# --- Stop Flag Mechanism ---
_main_thread_stop_requested = False
class StopMonitorRequested(Exception):
    pass

# Profiling function
def profile_func(frame, event, arg):
    global _main_thread_stop_requested, call_stack, call_tree
    if _main_thread_stop_requested:
        raise StopMonitorRequested()

    if event == 'call':
        try:
            code = frame.f_code
            filename = code.co_filename
            if filename.endswith('.py') and os.path.isfile(filename):
                normalized = filename.replace('\\', '/').lower()
                if 'lib' not in normalized and 'site-packages' not in normalized:
                    # Record unique definitions
                    defined_functions.add((code.co_name, filename, code.co_firstlineno))
                    # Record call hierarchy
                    depth = len(call_stack)
                    call_tree.append((code.co_name, filename, code.co_firstlineno, depth))
                    call_stack.append((code.co_name, filename, code.co_firstlineno))
        except Exception:
            pass
    elif event == 'return':
        if call_stack:
            try:
                call_stack.pop()
            except Exception:
                pass
        return
    else:
        return

    return profile_func

# Print summary including call hierarchy
def print_summary():
    if not defined_functions:
        print("[Monitor] Keine Funktionen gesammelt.")
        return
    print("\n🧠 Aufgerufene Funktionen (aus eigenen .py-Dateien):")
    cwd = os.getcwd()
    for funcname, path, line in sorted(defined_functions, key=lambda x: (x[1], x[2])):
        short = os.path.relpath(path, cwd)
        print(f" - {funcname}()  @ {short}:{line}")
    if call_tree:
        print("\n🗂 Aufrufhierarchie:")
        for funcname, path, line, depth in call_tree:
            short = os.path.relpath(path, cwd)
            indent = '  ' * depth
            print(f"{indent}- {funcname}()  @ {short}:{line}")
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
    script_dir = os.path.dirname(os.path.abspath(target_script))
    if script_dir and script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    try:
        os.chdir(script_dir)
    except Exception:
        pass

    stop_file = None
    if sys.platform == 'win32':
        stop_file = os.environ.get('MONITOR_STOP_FILE')
        if stop_file:
            threading.Thread(target=stop_file_watcher, args=(stop_file,), daemon=True).start()
        else:
            print("[Monitor] MONITOR_STOP_FILE nicht gesetzt.")

    sys.argv = [target_script] + sys.argv[3:]
    atexit.register(print_summary)

    if sys.platform != 'win32':
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, signal_handler)

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
        # Top control frame
        frm = ttk.Frame(self)
        frm.pack(padx=10, pady=10, fill='x')
        ttk.Label(frm, text='Script Path:').grid(row=0, column=0, sticky='w')
        self.path_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.path_var, width=80).grid(row=0, column=1, sticky='ew')
        ttk.Button(frm, text='Browse...', command=self.browse_file).grid(row=0, column=2, padx=5)

        ttk.Button(frm, text='Extract Definitions', command=self.on_extract).grid(row=1, column=0, pady=5, sticky='w')
        ttk.Button(frm, text='Show Hierarchy',    command=self.on_hierarchy).grid(row=1, column=1, pady=5, padx=5, sticky='w')
        self.btn_start = ttk.Button(frm, text='Start', command=self.on_start)
        self.btn_start.grid(row=1, column=2, pady=5, sticky='e')
        self.btn_stop  = ttk.Button(frm, text='Stop',  command=self.on_stop,  state='disabled')
        self.btn_stop.grid(row=1, column=3, pady=5, sticky='w')

        # Notebook for Monitor, Definitions, and Call Hierarchy
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Monitor tab
        mon_frame = ttk.Frame(self.notebook)
        self.notebook.add(mon_frame, text='Monitor')
        vscroll_mon = ttk.Scrollbar(mon_frame, orient='vertical')
        self.text = tk.Text(mon_frame, wrap='none', yscrollcommand=vscroll_mon.set)
        vscroll_mon.config(command=self.text.yview)
        vscroll_mon.pack(side='right', fill='y')
        self.text.pack(side='left', fill='both', expand=True)

        # Definitions tab
        def_frame = ttk.Frame(self.notebook)
        self.def_frame = def_frame
        self.notebook.add(def_frame, text='Definitions')
        vscroll_def = ttk.Scrollbar(def_frame, orient='vertical')
        self.def_text = tk.Text(def_frame, wrap='none', yscrollcommand=vscroll_def.set)
        vscroll_def.config(command=self.def_text.yview)
        vscroll_def.pack(side='right', fill='y')
        self.def_text.pack(side='left', fill='both', expand=True)

        # Call Hierarchy tab
        hier_frame = ttk.Frame(self.notebook)
        self.hier_frame = hier_frame
        self.notebook.add(hier_frame, text='Hierarchie')
        vscroll_hier = ttk.Scrollbar(hier_frame, orient='vertical')
        self.hier_text = tk.Text(hier_frame, wrap='none', yscrollcommand=vscroll_hier.set)
        vscroll_hier.config(command=self.hier_text.yview)
        vscroll_hier.pack(side='right', fill='y')
        self.hier_text.pack(side='left', fill='both', expand=True)

        # Context menus for copy
        self.monitor_menu = tk.Menu(self, tearoff=0)
        self.monitor_menu.add_command(label='Copy', command=lambda: self.copy_selection(self.text))
        self.text.bind('<Button-3>', lambda e: self.show_context_menu(e, self.monitor_menu))

        self.def_menu = tk.Menu(self, tearoff=0)
        self.def_menu.add_command(label='Copy', command=lambda: self.copy_selection(self.def_text))
        self.def_text.bind('<Button-3>', lambda e: self.show_context_menu(e, self.def_menu))

        self.hier_menu = tk.Menu(self, tearoff=0)
        self.hier_menu.add_command(label='Copy', command=lambda: self.copy_selection(self.hier_text))
        self.hier_text.bind('<Button-3>', lambda e: self.show_context_menu(e, self.hier_menu))

        # Sizegrip for resizing
        sizegrip = ttk.Sizegrip(self)
        sizegrip.pack(side='bottom', anchor='se')

    def show_context_menu(self, event, menu):
        menu.tk_popup(event.x_root, event.y_root)

    def copy_selection(self, widget):
        try:
            text = widget.selection_get()
            self.clipboard_clear()
            self.clipboard_append(text)
        except tk.TclError:
            pass

    def browse_file(self):
        path = filedialog.askopenfilename(filetypes=[('Python Files', '*.py')])
        if path:
            self.path_var.set(path)

    def on_start(self):
        path = self.path_var.get()
        if not path or not os.path.isfile(path):
            messagebox.showerror('Error', 'Ungültige Datei.')
            return
        if self.process and self.process.poll() is None:
            stop_monitor(self.process, self.stop_file)
        if self.stop_file and os.path.exists(self.stop_file):
            os.remove(self.stop_file)
        self.text.delete('1.0', tk.END)
        self.process, self.stop_file = start_monitor(path, self.text, self.btn_start, self.btn_stop)

    def on_stop(self):
        stop_monitor(self.process, self.stop_file)

    def on_extract(self):
        path = self.path_var.get()
        if not path or not os.path.isfile(path):
            messagebox.showerror('Error', 'Invalid file.')
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                source = f.read()
            tree = ast.parse(source)
            defs = []
            lines = source.splitlines()
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    start = node.lineno - 1
                    end = getattr(node, 'end_lineno', start + 1)
                    snippet = '\n'.join(lines[start:end])
                    defs.append(snippet)
            self.def_text.delete('1.0', tk.END)
            if defs:
                for snippet in defs:
                    self.def_text.insert(tk.END, snippet + '\n\n')
            else:
                self.def_text.insert(tk.END, 'No function or class definitions found.')
            self.notebook.select(self.notebook.index(self.def_frame))
        except Exception as e:
            messagebox.showerror('Error', f'Failed to extract definitions: {e}')

    def on_hierarchy(self):
        content = self.text.get('1.0', tk.END).splitlines()
        prefix = '🗂 Aufrufhierarchie:'
        start_idx = None
        for i, line in enumerate(content):
            if line.strip().startswith(prefix):
                start_idx = i + 1
                break
        self.hier_text.delete('1.0', tk.END)
        if start_idx is None or start_idx >= len(content):
            self.hier_text.insert(tk.END, 'Keine Aufrufhierarchie gefunden. Stelle sicher, dass das Monitoring beendet wurde und Hierarchie erzeugt wurde.')
        else:
            for line in content[start_idx:]:
                if not line.strip():
                    continue
                if line.lstrip().startswith('-') or line.startswith(' '):
                    self.hier_text.insert(tk.END, line + '\n')
                else:
                    break
        self.notebook.select(self.hier_frame)

    def on_closing(self):
        if self.process and self.process.poll() is None:
            stop_monitor(self.process, self.stop_file)
        if self.stop_file and os.path.exists(self.stop_file):
            os.remove(self.stop_file)
        self.destroy()

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'monitor':
        if len(sys.argv) < 3:
            print('Usage: monitor <script.py>')
        else:
            wrapper_main(sys.argv[2])
    else:
        app = App()
        app.protocol('WM_DELETE_WINDOW', app.on_closing)
        app.mainloop()
