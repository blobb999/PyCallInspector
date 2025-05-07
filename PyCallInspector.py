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
import json
import logging
from functools import lru_cache

# --- Setup Logger for the monitor part ---
# This logger will be used by the monitor process.
# The GUI part can have its own way of displaying messages or use print for GUI console.
logger = logging.getLogger("PyCallInspectorMonitor")
# Configure logger (basic configuration, can be enhanced)
# For now, let monitor messages print to stdout/stderr which is captured by GUI.
# A more sophisticated setup might involve a dedicated log file or queue for GUI display.

# --- Profiler State and Logic ---
class ProfilerState:
    __slots__ = ["defined_functions", "call_stack", "call_tree", 
                 "marker_a_index", "marker_b_index", "stop_requested",
                 "results_file_path", "target_script_abs_path"]

    def __init__(self, results_file_path=None, target_script_abs_path=None):
        self.defined_functions = set()  # Stores (name, abs_path, line)
        self.call_stack = []
        self.call_tree = []  # Stores (name, abs_path, line, depth)
        self.marker_a_index = None
        self.marker_b_index = None
        self.stop_requested = False
        self.results_file_path = results_file_path
        self.target_script_abs_path = target_script_abs_path

    def reset(self):
        self.defined_functions.clear()
        self.call_stack.clear()
        self.call_tree.clear()
        self.marker_a_index = None
        self.marker_b_index = None
        self.stop_requested = False
        # results_file_path and target_script_abs_path are set at init and don persist across resets in current flow

    def profile_method(self, frame, event, arg):
        if self.stop_requested:
            raise StopMonitorRequested()

        if event == 'call':
            try:
                code = frame.f_code
                # Use a cached version for abspath to avoid repeated computations for same file
                filename = self._cached_abspath(code.co_filename)
                
                if filename.endswith('.py') and os.path.isfile(filename):
                    normalized = filename.replace('\\', '/').lower()
                    # Exclude library code more robustly
                    # Check against sys.prefix and sys.exec_prefix common paths
                    # This is a basic check; a more robust one might involve checking against all sys.path entries that are not user script dirs
                    if not any(normalized.startswith(p.lower().replace('\\', '/')) for p in [sys.prefix, sys.exec_prefix]) or self.target_script_abs_path and normalized.startswith(os.path.dirname(self.target_script_abs_path).lower().replace('\\', '/')):
                        func_name = code.co_name
                        line_no = code.co_firstlineno
                        self.defined_functions.add((func_name, filename, line_no))
                        depth = len(self.call_stack)
                        self.call_tree.append((func_name, filename, line_no, depth))
                        self.call_stack.append((func_name, filename, line_no))
            except Exception as e:
                logger.error(f"Error in profiler (call event): {e}", exc_info=True)
        elif event == 'return':
            if self.call_stack:
                try:
                    self.call_stack.pop()
                except IndexError:
                    # This should ideally not happen if calls/returns are balanced
                    logger.warning("Profiler stack underflow on return.")
                except Exception as e:
                    logger.error(f"Error in profiler (return event): {e}", exc_info=True)
        return self.profile_method

    @lru_cache(maxsize=128)
    def _cached_abspath(self, path_str):
        return os.path.abspath(path_str)

    @lru_cache(maxsize=128)
    def _cached_relpath(self, path_str, start_path):
        try:
            return os.path.relpath(path_str, start_path)
        except ValueError:
            return path_str # If on different drive, keep absolute
        except Exception as e:
            logger.warning(f"Could not get relpath for {path_str} from {start_path}: {e}")
            return path_str

    def print_summary_method(self):
        # Determine the slice of the call tree based on markers
        start_index = self.marker_a_index if self.marker_a_index is not None else 0
        end_index = self.marker_b_index if self.marker_b_index is not None else len(self.call_tree)

        if self.marker_a_index is not None and self.marker_b_index is not None and self.marker_a_index > self.marker_b_index:
            logger.warning("Marker B was set before Marker A. Ignoring Marker B.")
            print("[Monitor] Warning: Marker B was set before Marker A. Ignoring Marker B.")
            end_index = len(self.call_tree)

        active_call_tree = self.call_tree[start_index:end_index]
        active_funcs = set()
        if active_call_tree:
            active_funcs = {(name, path, line) for name, path, line, depth in active_call_tree}
        
        filtered_defs_set = {item for item in active_funcs if item[0] != '<genexpr>'}

        if self.results_file_path:
            try:
                with open(self.results_file_path, 'w', encoding='utf-8') as f:
                    json.dump(list(filtered_defs_set), f)
                print(f"[Monitor] Filtered definitions saved to {self.results_file_path}")
            except Exception as e:
                logger.error(f"Error saving filtered definitions to {self.results_file_path}: {e}", exc_info=True)
                print(f"[Monitor] Error saving filtered definitions: {e}")

        print("\n🧠 Called Functions (from own .py files" + (
            " in marked section" if self.marker_a_index is not None or self.marker_b_index is not None else "") + "):")
        if not filtered_defs_set:
            print("  (None or only <genexpr>)")
        else:
            cwd = None
            try:
                cwd = os.getcwd()
            except OSError as e:
                logger.warning(f"Could not get current working directory: {e}")
            
            for funcname, path, line in sorted(filtered_defs_set, key=lambda x: (x[1], x[2])):
                short = self._cached_relpath(path, cwd) if cwd else path
                print(f" - {funcname}()  @ {short}:{line}")

        print("\n🗂 Call Hierarchy" + (" (between markers)" if self.marker_a_index is not None or self.marker_b_index is not None else "") + ":")
        if not active_call_tree:
            print("  (No calls collected" + (")" if self.marker_a_index is None else " in marked section)"))
        else:
            filtered_tree = [item for item in active_call_tree if item[0] != '<genexpr>']
            if not filtered_tree:
                print("  (Only <genexpr> calls in marked section)")
            else:
                cwd = None
                try:
                    cwd = os.getcwd()
                except OSError as e:
                    logger.warning(f"Could not get current working directory for hierarchy: {e}")

                for funcname, path, line, depth in filtered_tree:
                    short = self._cached_relpath(path, cwd) if cwd else path
                    indent = '  ' * depth
                    print(f"{indent}- {funcname}()  @ {short}:{line}")
        sys.stdout.flush()

    def request_stop_method(self):
        if not self.stop_requested:
            print("[Monitor] Stop signal detected. Flag set.")
            self.stop_requested = True

    def set_marker_a_method(self):
        self.marker_a_index = len(self.call_tree)
        print(f"[Monitor] Marker A set at index {self.marker_a_index}")
        sys.stdout.flush()

    def set_marker_b_method(self):
        self.marker_b_index = len(self.call_tree)
        print(f"[Monitor] Marker B set at index {self.marker_b_index}")
        sys.stdout.flush()

# Global instance for the current monitor process (to be accessed by callbacks)
_profiler_instance = None

class StopMonitorRequested(Exception):
    pass

# Signal handler (Unix)
def signal_handler_unix(signum, frame):
    if _profiler_instance and not _profiler_instance.stop_requested:
        print(f"[Monitor] Signal {signum} received, stop flag set.")
        _profiler_instance.request_stop_method()

# File watcher for stop/marker signals
def file_watcher(file_path, callback_method_on_instance):
    while True:
        if _profiler_instance and _profiler_instance.stop_requested:
            break
        if os.path.exists(file_path):
            callback_method_on_instance() # Call the bound method of _profiler_instance
            try:
                os.remove(file_path)
            except OSError as e:
                logger.error(f"Error deleting signal file {file_path}: {e}", exc_info=True)
                print(f"[Monitor] Error deleting signal file {file_path}: {e}")
        time.sleep(0.2)

# Main wrapper to run target under profiler
def wrapper_main(target_script):
    global _profiler_instance
    
    target_script_abs = os.path.abspath(target_script)
    results_file_env = os.environ.get('MONITOR_RESULTS_FILE')
    _profiler_instance = ProfilerState(results_file_path=results_file_env, target_script_abs_path=target_script_abs)
    # _profiler_instance.reset() # Already clean from __init__

    script_dir = os.path.dirname(target_script_abs)
    if script_dir and script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    try:
        os.chdir(script_dir)
    except Exception as e:
        logger.warning(f"Failed to change CWD to {script_dir}: {e}", exc_info=True)
        print(f"[Monitor] Warning: Failed to change CWD to {script_dir}: {e}")

    stop_file = os.environ.get('MONITOR_STOP_FILE')
    marker_a_file = os.environ.get('MONITOR_MARKER_A_FILE')
    marker_b_file = os.environ.get('MONITOR_MARKER_B_FILE')

    if stop_file:
        threading.Thread(target=file_watcher, args=(stop_file, _profiler_instance.request_stop_method), daemon=True).start()
    if marker_a_file:
        threading.Thread(target=file_watcher, args=(marker_a_file, _profiler_instance.set_marker_a_method), daemon=True).start()
    if marker_b_file:
        threading.Thread(target=file_watcher, args=(marker_b_file, _profiler_instance.set_marker_b_method), daemon=True).start()

    if sys.platform != 'win32':
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, signal_handler_unix)
            except ValueError:
                logger.warning(f"Could not set signal handler for {sig} in thread.")

    sys.argv = [target_script_abs] + sys.argv[3:]
    atexit.register(_profiler_instance.print_summary_method)
    sys.setprofile(_profiler_instance.profile_method)

    try:
        print(f"[Monitor] Starting {target_script_abs} with CWD={os.getcwd()} args={sys.argv} via runpy")
        runpy.run_path(target_script_abs, run_name='__main__')
        print("[Monitor] Target script finished normally.")
    except StopMonitorRequested:
        print("[Monitor] Stop request received, interruption successful.")
    except SystemExit as e:
        exit_code = getattr(e, 'code', 0)
        if exit_code != 0:
            print(f"[Monitor] Target script finished with code {exit_code}.")
        else:
            print("[Monitor] Target script finished via sys.exit(0).")
    except Exception as e:
        logger.error(f"Error executing {target_script_abs}: {e}", exc_info=True)
        print(f"[Monitor] Error executing {target_script_abs}: {e}")
        # traceback.print_exc() # Already logged with exc_info
    finally:
        sys.setprofile(None)
        print("[Monitor] Profiling stopped (finally).")

# --- GUI Code --- #
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PyCallInspector")
        self.geometry("800x650") # Increased height for progressbar

        self.process = None
        self.pid = os.getpid()
        self.signal_dir = tempfile.gettempdir()
        self.stop_file = os.path.join(self.signal_dir, f"pycallinspector_{self.pid}.stop")
        self.marker_a_file = os.path.join(self.signal_dir, f"pycallinspector_{self.pid}.mark_a")
        self.marker_b_file = os.path.join(self.signal_dir, f"pycallinspector_{self.pid}.mark_b")
        self.results_file = os.path.join(self.signal_dir, f"pycallinspector_{self.pid}.results.json")

        self.marker_state = 'None'
        self.last_monitored_script = None

        self.create_widgets()
        self.cleanup_signal_files()

    def cleanup_signal_files(self):
        for f in [self.stop_file, self.marker_a_file, self.marker_b_file, self.results_file]:
            if f and os.path.exists(f):
                try:
                    os.remove(f)
                except OSError as e:
                    # Log to GUI console or a GUI status bar if available
                    # For now, print to stderr, which might not be visible if running pythonw.exe
                    logger.warning(f"GUI: Error cleaning up signal file {f}: {e}")
                    # messagebox.showwarning("Cleanup Error", f"Could not remove temporary file {f}:\n{e}") # Too noisy

    def create_widgets(self):
        # Top control frame
        top_frm = ttk.Frame(self)
        top_frm.pack(padx=10, pady=10, fill='x')
        top_frm.columnconfigure(1, weight=1)

        ttk.Label(top_frm, text='Script Path:').grid(row=0, column=0, sticky='w', padx=(0, 5))
        self.path_var = tk.StringVar()
        ttk.Entry(top_frm, textvariable=self.path_var).grid(row=0, column=1, sticky='ew')
        ttk.Button(top_frm, text='Browse...', command=self.browse_file).grid(row=0, column=2, padx=5)

        # Button frame
        btn_frm = ttk.Frame(self)
        btn_frm.pack(padx=10, pady=(0,5), fill='x') # Reduced pady

        ttk.Button(btn_frm, text='Extract Definitions', command=self.on_extract).pack(side='left')
        ttk.Button(btn_frm, text='Show Hierarchy', command=self.on_hierarchy).pack(side='left', padx=5)

        self.btn_stop  = ttk.Button(btn_frm, text='Stop',  command=self.on_stop,  state='disabled')
        self.btn_stop.pack(side='right')
        self.btn_marker = ttk.Button(btn_frm, text='Set Marker A', command=self.on_set_marker, state='disabled')
        self.btn_marker.pack(side='right', padx=5)
        self.btn_start = ttk.Button(btn_frm, text='Start', command=self.on_start)
        self.btn_start.pack(side='right')

        # Progress bar frame
        progress_frm = ttk.Frame(self)
        progress_frm.pack(padx=10, pady=(0,10), fill='x')
        self.progress_var = tk.DoubleVar()
        self.progressbar = ttk.Progressbar(progress_frm, mode='indeterminate', variable=self.progress_var)
        self.progressbar.pack(fill='x', expand=True)

        # Notebook
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=0)

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

        # Hierarchy tab
        hier_frame = ttk.Frame(self.notebook)
        self.hier_frame = hier_frame
        self.notebook.add(hier_frame, text='Hierarchy')
        vscroll_hier = ttk.Scrollbar(hier_frame, orient='vertical')
        self.hier_text = tk.Text(hier_frame, wrap='none', yscrollcommand=vscroll_hier.set)
        vscroll_hier.config(command=self.hier_text.yview)
        vscroll_hier.pack(side='right', fill='y')
        self.hier_text.pack(side='left', fill='both', expand=True)

        self.monitor_menu = self.create_context_menu(self.text)
        self.text.bind('<Button-3>', lambda e: self.show_context_menu(e, self.monitor_menu))
        self.def_menu = self.create_context_menu(self.def_text)
        self.def_text.bind('<Button-3>', lambda e: self.show_context_menu(e, self.def_menu))
        self.hier_menu = self.create_context_menu(self.hier_text)
        self.hier_text.bind('<Button-3>', lambda e: self.show_context_menu(e, self.hier_menu))

        sizegrip = ttk.Sizegrip(self)
        sizegrip.pack(side='bottom', anchor='se')

    def create_context_menu(self, widget):
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label='Copy', command=lambda w=widget: self.copy_selection(w))
        menu.add_command(label='Select All', command=lambda w=widget: self.select_all_text(w))
        return menu

    def show_context_menu(self, event, menu):
        if event.widget.winfo_exists():
            menu.tk_popup(event.x_root, event.y_root)

    def copy_selection(self, widget):
        if not widget.winfo_exists(): return
        try:
            text = widget.selection_get()
            self.clipboard_clear()
            self.clipboard_append(text)
        except tk.TclError:
            pass # No selection

    def select_all_text(self, widget):
        if not widget.winfo_exists(): return
        widget.tag_add(tk.SEL, "1.0", tk.END)
        widget.mark_set(tk.INSERT, "1.0")
        widget.see(tk.INSERT)
        return 'break'

    def browse_file(self):
        path = filedialog.askopenfilename(filetypes=[('Python Files', '*.py'), ('All files', '*.*')])
        if path:
            self.path_var.set(os.path.abspath(path))

    def start_monitor_gui_thread(self, script_path):
        self.progressbar.start(10) # Start indeterminate progress bar
        self.process = start_monitor_subprocess(
            script_path,
            self.text,
            self.btn_start,
            self.btn_stop,
            self.btn_marker,
            self.marker_a_file,
            self.marker_b_file,
            self.stop_file,
            self.results_file
        )
        if self.process:
            self.notebook.select(0)
        else:
            self.btn_start.config(state='normal')
            self.btn_stop.config(state='disabled')
            self.btn_marker.config(state='disabled')
            self.last_monitored_script = None
            self.progressbar.stop()

    def on_start(self):
        path = self.path_var.get()
        if not path or not os.path.isfile(path):
            messagebox.showerror('Error', 'Invalid or non-existent script file.')
            return

        if self.process and self.process.poll() is None:
            signal_stop_monitor_subprocess(self.process, self.stop_file)
            # Wait for process to actually stop? Or assume reader thread handles button state

        self.cleanup_signal_files()
        self.marker_state = 'None'
        self.btn_marker.config(text="Set Marker A", state='disabled')
        self.text.delete('1.0', tk.END)
        self.def_text.delete('1.0', tk.END)
        self.hier_text.delete('1.0', tk.END)
        self.last_monitored_script = path
        
        # Run start_monitor in a separate thread to keep GUI responsive if Popen blocks for any reason
        # (though Popen itself is non-blocking for stdout/stderr pipes)
        # The main benefit is that the reader thread is started from there.
        # For now, direct call is fine as Popen is quick.
        self.start_monitor_gui_thread(path)

    def on_stop(self):
        signal_stop_monitor_subprocess(self.process, self.stop_file)
        # Progressbar is stopped in the reader thread when process ends

    def on_set_marker(self):
        if not self.process or self.process.poll() is not None:
            messagebox.showwarning("Marker", "Monitoring must be running to set markers.")
            return

        if self.marker_state == 'None':
            signal_set_marker_subprocess(self.marker_a_file)
            self.marker_state = 'A_Set'
            self.btn_marker.config(text="Set Marker B")
            self.text.insert(tk.END, "\n[GUI] Marker A signal sent.\n")
            self.text.see(tk.END)
        elif self.marker_state == 'A_Set':
            signal_set_marker_subprocess(self.marker_b_file)
            self.marker_state = 'B_Set'
            self.btn_marker.config(text="Clear Markers")
            self.text.insert(tk.END, "\n[GUI] Marker B signal sent.\n")
            self.text.see(tk.END)
        elif self.marker_state == 'B_Set':
            if os.path.exists(self.marker_a_file):
                try:
                    os.remove(self.marker_a_file)
                except OSError:
                    logger.warning("GUI: Failed to remove marker_a_file on clear.")
            if os.path.exists(self.marker_b_file):
                try:
                    os.remove(self.marker_b_file)
                except OSError:
                    logger.warning("GUI: Failed to remove marker_b_file on clear.")
            if os.path.exists(self.results_file):
                try:
                    os.remove(self.results_file)
                except OSError:
                    logger.warning("GUI: Failed to remove results_file on clear.")
            self.marker_state = 'None'
            self.btn_marker.config(text="Set Marker A")
            self.text.insert(tk.END, "\n[GUI] Markers cleared (local status & results file reset).\n")
            self.text.see(tk.END)

    def on_extract(self):
        self.progressbar.start(10) # Start progress bar for extraction
        self.update_idletasks() # Ensure GUI updates

        path = self.last_monitored_script if self.last_monitored_script else self.path_var.get()
        if not path or not os.path.isfile(path):
            messagebox.showerror('Error', 'Invalid or non-existent script file.')
            self.progressbar.stop()
            return

        called_funcs_filter = None
        try:
            if os.path.exists(self.results_file):
                with open(self.results_file, 'r', encoding='utf-8') as f:
                    loaded_list = json.load(f)
                current_script_abs = os.path.abspath(path)
                called_funcs_filter = {(name, line) for name, pth, line in loaded_list if os.path.abspath(pth) == current_script_abs}
        except FileNotFoundError:
            pass
        except json.JSONDecodeError as e:
            messagebox.showwarning("Filter Error", f"Results file could not be read ({e}). Showing all definitions.")
        except Exception as e:
            messagebox.showwarning("Filter Error", f"Unexpected error loading filter ({e}). Showing all definitions.")

        try:
            encoding = 'utf-8'
            try:
                import chardet # Optional dependency
                with open(path, 'rb') as f_raw:
                    detected = chardet.detect(f_raw.read(4096))
                    if detected['encoding'] and detected['confidence'] > 0.7:
                        encoding = detected['encoding']
            except ImportError:
                pass # chardet not installed
            except Exception:
                pass # Other detection error

            with open(path, 'r', encoding=encoding, errors='replace') as f:
                source = f.read()
            tree = ast.parse(source, filename=path)
            defs_to_show = []
            lines = source.splitlines()
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    name = node.name
                    lineno = node.lineno
                    if called_funcs_filter is not None and (name, lineno) not in called_funcs_filter:
                        continue
                    start = lineno - 1
                    end = getattr(node, 'end_lineno', None)
                    if end is None:
                        try: end = start + len(ast.unparse(node).splitlines()) # Requires Python 3.9+
                        except AttributeError: # Fallback for older ast or if unparse fails
                            # Crude estimation, find next node at same or lesser indent or EOF
                            end = start + 1 
                            for i in range(start + 1, len(lines)):
                                if lines[i].strip() == "" or lines[i].startswith(" " * (node.col_offset +1)) : # part of func
                                     end = i +1
                                else:
                                     break # Dedent or different construct
                    snippet = '\n'.join(lines[start:end])
                    defs_to_show.append((name, lineno, snippet))

            self.def_text.delete('1.0', tk.END)
            if defs_to_show:
                defs_to_show.sort(key=lambda item: item[1])
                filter_active = called_funcs_filter is not None
                self.def_text.insert(tk.END, f"--- {len(defs_to_show)} definitions found" + (" (filtered by marker calls)" if filter_active else "") + " ---\n\n")
                for name, lineno, snippet in defs_to_show:
                    self.def_text.insert(tk.END, f"# --- Definition: {name} (Line: {lineno}) ---\n")
                    self.def_text.insert(tk.END, snippet + '\n\n')
            else:
                if called_funcs_filter is not None:
                    self.def_text.insert(tk.END, 'None of the functions/classes called in the marked section were found.')
                else:
                    self.def_text.insert(tk.END, 'No function or class definitions found.')
            self.notebook.select(self.def_frame)
        except Exception as e:
            messagebox.showerror('Error During Extraction', f'Definitions could not be extracted:\n{e}')
        finally:
            self.progressbar.stop()

    def on_hierarchy(self):
        self.progressbar.start(10)
        self.update_idletasks()
        try:
            content = self.text.get('1.0', tk.END).splitlines()
        except tk.TclError:
             messagebox.showerror("Error", "Monitor output could not be read.")
             self.progressbar.stop()
             return

        prefix = '🗂 Call Hierarchy'
        start_idx = -1
        for i, line in enumerate(content):
            if line.strip().startswith(prefix):
                start_idx = i + 1
                break

        self.hier_text.delete('1.0', tk.END)
        if start_idx == -1 or start_idx >= len(content):
            self.hier_text.insert(tk.END, 'No call hierarchy found in monitor output.\nEnsure monitoring has finished.')
        else:
            found_hierarchy = False
            for line in content[start_idx:]:
                if line.startswith('[') and not line.startswith('[Monitor]'):
                     break
                if line.strip().startswith('-') or (line.startswith(' ') and line.lstrip().startswith('-')):
                    self.hier_text.insert(tk.END, line + '\n')
                    found_hierarchy = True
                elif found_hierarchy and not line.strip(): # Allow blank lines within hierarchy
                    self.hier_text.insert(tk.END, line + '\n')
                elif found_hierarchy and line.strip(): # Stop if content appears after hierarchy and blank lines
                    break
            if not found_hierarchy:
                 self.hier_text.insert(tk.END, 'No call hierarchy lines found after the header.')
        self.notebook.select(self.hier_frame)
        self.progressbar.stop()

    def on_closing(self):
        if self.process and self.process.poll() is None:
            signal_stop_monitor_subprocess(self.process, self.stop_file)
        self.cleanup_signal_files()
        self.destroy()

# Renamed GUI helper functions to avoid conflict if this script is run directly for GUI
def start_monitor_subprocess(script_path, text_widget, start_button, stop_button, marker_button, marker_a_file, marker_b_file, stop_file, results_file):
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'
    env['MONITOR_STOP_FILE'] = stop_file
    env['MONITOR_MARKER_A_FILE'] = marker_a_file
    env['MONITOR_MARKER_B_FILE'] = marker_b_file
    env['MONITOR_RESULTS_FILE'] = results_file

    cmd = [sys.executable, '-u', __file__, 'monitor', script_path]
    process = None
    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1,
            text=True, encoding='utf-8', errors='replace', env=env
        )
    except Exception as e:
        messagebox.showerror("Error Starting", f"Monitor process could not be started:\n{e}")
        if start_button.winfo_exists(): start_button.config(state='normal') # Re-enable start if failed
        if stop_button.winfo_exists(): stop_button.config(state='disabled')
        if marker_button.winfo_exists(): marker_button.config(state='disabled')
        return None

    if start_button.winfo_exists(): start_button.config(state='disabled')
    if stop_button.winfo_exists(): stop_button.config(state='normal')
    if marker_button.winfo_exists(): marker_button.config(state='normal')

    def reader_thread_target():
        try:
            for line in process.stdout:
                if text_widget.winfo_exists():
                    text_widget.insert(tk.END, line)
                    text_widget.see(tk.END)
        except Exception as e:
            if text_widget.winfo_exists():
                 text_widget.insert(tk.END, f"\n[GUI] Error reading output: {e}\n")
        finally:
            if process.stdout: process.stdout.close()
            process.wait()
            if text_widget.winfo_exists(): # Check all widgets before configuring
                if start_button.winfo_exists(): start_button.config(state='normal')
                if stop_button.winfo_exists(): stop_button.config(state='disabled')
                if marker_button.winfo_exists(): marker_button.config(state='disabled')
                text_widget.insert(tk.END, "\n[GUI] Monitor process finished.\n")
                text_widget.see(tk.END)
                if hasattr(text_widget.master.master, 'progressbar'): # Access progress bar via app instance
                    text_widget.master.master.progressbar.stop()
            
            # Final cleanup of signal files (excluding results_file)
            for f_path in [stop_file, marker_a_file, marker_b_file]:
                if f_path and os.path.exists(f_path):
                    try: os.remove(f_path)
                    except OSError: logger.warning(f"GUI: Failed to remove signal file {f_path} in reader thread.")

    threading.Thread(target=reader_thread_target, daemon=True).start()
    return process

def signal_stop_monitor_subprocess(process, stop_file):
    if process and process.poll() is None:
        print(f"[GUI] Sending stop signal via file: {stop_file}")
        try:
            with open(stop_file, 'w') as f: f.write('stop')
        except Exception as e:
             print(f"[GUI] Error creating stop file: {e}")
             logger.error(f"GUI: Error creating stop file {stop_file}: {e}", exc_info=True)

def signal_set_marker_subprocess(marker_file):
     print(f"[GUI] Sending marker signal via file: {marker_file}")
     try:
         with open(marker_file, 'w') as f: f.write('mark')
     except Exception as e:
          print(f"[GUI] Error creating marker file: {e}")
          logger.error(f"GUI: Error creating marker file {marker_file}: {e}", exc_info=True)

# --- Main Execution --- #
if __name__ == '__main__':
    # Basic logger configuration for the main GUI process (if any messages are logged here)
    # For the monitor subprocess, its own logger is configured if it's run as __main__.
    # If this script is run directly, set up a basic console handler for the root logger.
    if not sys.argv[1:] or sys.argv[1] != 'monitor':
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    if len(sys.argv) > 1 and sys.argv[1] == 'monitor':
        # Configure logger for monitor process when run this way
        # (e.g., write to a specific file or use a specific format)
        # For now, it will inherit root or use its own if configured in monitor-specific block
        # logger.info("Monitor process started via __main__") # Example
        if len(sys.argv) < 3:
            print('Usage: python pycallinspector_en.py monitor <script_to_monitor.py> [script_args...]')
            sys.exit(1)
        target_script_path = sys.argv[2]
        wrapper_main(target_script_path)
    else:
        app = App()
        app.protocol('WM_DELETE_WINDOW', app.on_closing)
        app.mainloop()

