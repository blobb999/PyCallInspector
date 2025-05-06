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
import json # Added for saving/loading results

# Global sets and lists to store called functions and call hierarchy
defined_functions = set() # Stores all unique functions encountered (name, path, line)
call_stack = []
call_tree = [] # Stores all calls (name, path, line, depth)

# --- Marker Mechanism ---
marker_a_index = None
marker_b_index = None

# --- Stop Flag Mechanism ---
_main_thread_stop_requested = False
class StopMonitorRequested(Exception):
    pass

# Profiling function
def profile_func(frame, event, arg):
    global _main_thread_stop_requested, call_stack, call_tree, defined_functions
    if _main_thread_stop_requested:
        raise StopMonitorRequested()

    if event == 'call':
        try:
            code = frame.f_code
            filename = os.path.abspath(code.co_filename) # Use absolute path
            if filename.endswith('.py') and os.path.isfile(filename):
                normalized = filename.replace('\\', '/').lower()
                # Exclude library code
                if 'lib' not in normalized and 'site-packages' not in normalized:
                    func_name = code.co_name
                    line_no = code.co_firstlineno
                    # Record unique definitions (using absolute path)
                    defined_functions.add((func_name, filename, line_no))
                    # Record call hierarchy (using absolute path)
                    depth = len(call_stack)
                    call_tree.append((func_name, filename, line_no, depth))
                    call_stack.append((func_name, filename, line_no))
        except Exception:
            pass # Ignore errors during profiling
    elif event == 'return':
        if call_stack:
            try:
                call_stack.pop()
            except IndexError:
                pass # Stack underflow, should ideally not happen
            except Exception:
                pass # Ignore other errors during profiling
        return
    else:
        return

    return profile_func

# Print summary including call hierarchy, considering markers
def print_summary(results_file_path=None):
    global marker_a_index, marker_b_index, call_tree

    # Determine the slice of the call tree based on markers
    start_index = marker_a_index if marker_a_index is not None else 0
    end_index = marker_b_index if marker_b_index is not None else len(call_tree)

    # Ensure start_index is not after end_index if both are set
    if marker_a_index is not None and marker_b_index is not None and marker_a_index > marker_b_index:
        print("[Monitor] Warnung: Marker B wurde vor Marker A gesetzt. Ignoriere Marker B.")
        end_index = len(call_tree)

    # Slice the call tree
    active_call_tree = call_tree[start_index:end_index]

    # Derive the set of unique functions *called within the active slice*
    active_funcs = set()
    if active_call_tree:
        # Store as (name, abs_path, line)
        active_funcs = { (name, path, line) for name, path, line, depth in active_call_tree }

    # Filter out <genexpr> from the functions called within the active slice
    filtered_defs_set = {item for item in active_funcs if item[0] != '<genexpr>'}

    # --- Save filtered definitions to results file for GUI --- #
    if results_file_path:
        try:
            results_list = list(filtered_defs_set)
            with open(results_file_path, 'w', encoding='utf-8') as f:
                json.dump(results_list, f)
            print(f"[Monitor] Gefilterte Definitionen gespeichert in {results_file_path}")
        except Exception as e:
            print(f"[Monitor] Fehler beim Speichern der gefilterten Definitionen: {e}")
    # --- End Save --- #

    # --- Print Summary to Console --- #
    print("\n🧠 Aufgerufene Funktionen (aus eigenen .py-Dateien" + (
" im markierten Bereich" if marker_a_index is not None or marker_b_index is not None else "") + "):")
    if not filtered_defs_set:
        print("  (Keine oder nur <genexpr>)")
    else:
        # Use absolute paths for printing, convert to relative for display
        try:
            cwd = os.getcwd()
        except OSError:
            cwd = None # Handle cases where CWD might not be accessible

        for funcname, path, line in sorted(filtered_defs_set, key=lambda x: (x[1], x[2])):
            short = path
            if cwd:
                try:
                    short = os.path.relpath(path, cwd)
                except ValueError:
                    pass # Keep absolute path if relpath fails (e.g., different drive)
            print(f" - {funcname}()  @ {short}:{line}")

    print("\n🗂 Aufrufhierarchie" + (" (zwischen Markern)" if marker_a_index is not None or marker_b_index is not None else "") + ":")
    if not active_call_tree:
        print("  (Keine Aufrufe gesammelt" + (")" if marker_a_index is None else " im markierten Bereich)"))
    else:
        # Filter out <genexpr> from the active call tree slice
        filtered_tree = [item for item in active_call_tree if item[0] != '<genexpr>']
        if not filtered_tree:
             print("  (Nur <genexpr> Aufrufe im markierten Bereich)")
        else:
            try:
                cwd = os.getcwd()
            except OSError:
                cwd = None

            for funcname, path, line, depth in filtered_tree:
                short = path
                if cwd:
                    try:
                        short = os.path.relpath(path, cwd)
                    except ValueError:
                        pass
                indent = '  ' * depth
                print(f"{indent}- {funcname}()  @ {short}:{line}")
    # --- End Print Summary --- #

    sys.stdout.flush()

# Signal handler (Unix)
def signal_handler(signum, frame):
    global _main_thread_stop_requested
    if not _main_thread_stop_requested:
        print(f"[Monitor] Signal {signum} erhalten, Stop-Flag gesetzt.")
        sys.stdout.flush()
        _main_thread_stop_requested = True

# File watcher for stop/marker signals (Windows or Unix)
def file_watcher(file_path, callback):
    while True: # Keep watching until monitor process ends
        if _main_thread_stop_requested: # Stop watching if main thread is stopping
            break
        if os.path.exists(file_path):
            callback()
            try:
                os.remove(file_path)
            except OSError as e:
                print(f"[Monitor] Fehler beim Löschen der Signaldatei {file_path}: {e}")
            # No break here, watcher thread lives until monitor process ends
        time.sleep(0.2) # Check less frequently

# Callback functions for watchers
def set_stop_flag():
    global _main_thread_stop_requested
    if not _main_thread_stop_requested:
        print(f"[Monitor] Stop-Signal erkannt. Flag gesetzt.")
        _main_thread_stop_requested = True

def set_marker_a():
    global marker_a_index, call_tree
    marker_a_index = len(call_tree)
    print(f"[Monitor] Marker A gesetzt bei Index {marker_a_index}")
    sys.stdout.flush()

def set_marker_b():
    global marker_b_index, call_tree
    marker_b_index = len(call_tree)
    print(f"[Monitor] Marker B gesetzt bei Index {marker_b_index}")
    sys.stdout.flush()

# Main wrapper to run target under profiler
def wrapper_main(target_script):
    global marker_a_index, marker_b_index, defined_functions, call_stack, call_tree, _main_thread_stop_requested
    # Reset globals for this run
    defined_functions.clear()
    call_stack.clear()
    call_tree.clear()
    marker_a_index = None
    marker_b_index = None
    _main_thread_stop_requested = False

    target_script_abs = os.path.abspath(target_script)
    script_dir = os.path.dirname(target_script_abs)
    # Add script's directory to path for local imports
    if script_dir and script_dir not in sys.path:
        # print(f"[Monitor] Adding script directory to sys.path: {script_dir}") # Debug
        sys.path.insert(0, script_dir)
    # Change CWD to script's directory
    try:
        os.chdir(script_dir)
        # print(f"[Monitor] Changed CWD to: {script_dir}") # Debug
    except Exception as e:
        print(f"[Monitor] Warning: Failed to change CWD to {script_dir}: {e}")

    # --- Setup Signal Handling and Watchers ---
    stop_file = os.environ.get('MONITOR_STOP_FILE')
    marker_a_file = os.environ.get('MONITOR_MARKER_A_FILE')
    marker_b_file = os.environ.get('MONITOR_MARKER_B_FILE')
    results_file_path = os.environ.get('MONITOR_RESULTS_FILE') # Get results file path

    if stop_file:
        threading.Thread(target=file_watcher, args=(stop_file, set_stop_flag), daemon=True).start()
    if marker_a_file:
        threading.Thread(target=file_watcher, args=(marker_a_file, set_marker_a), daemon=True).start()
    if marker_b_file:
        threading.Thread(target=file_watcher, args=(marker_b_file, set_marker_b), daemon=True).start()

    # Setup signal handlers for Unix-like systems
    if sys.platform != 'win32':
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, signal_handler)
            except ValueError:
                pass
    # --- End Setup ---

    # Set target script arguments
    sys.argv = [target_script_abs] + sys.argv[3:] # Use absolute path for target

    # Register summary function to run at exit, passing the results file path
    atexit.register(print_summary, results_file_path=results_file_path)

    # Start profiling
    sys.setprofile(profile_func)

    try:
        print(f"[Monitor] Starte {target_script_abs} mit CWD={os.getcwd()} args={sys.argv} via runpy")
        # Execute the target script
        runpy.run_path(target_script_abs, run_name='__main__')
        print("[Monitor] Ziel-Skript normal beendet.")
    except StopMonitorRequested:
        print("[Monitor] Stop-Anfrage empfangen, Unterbrechung erfolgreich.")
    except SystemExit as e:
        exit_code = getattr(e, 'code', 0)
        if exit_code != 0:
            print(f"[Monitor] Ziel-Skript mit Code {exit_code} beendet.")
        else:
            print("[Monitor] Ziel-Skript via sys.exit(0) beendet.")
    except Exception as e:
        import traceback
        print(f"[Monitor] Fehler beim Ausführen von {target_script_abs}: {e}")
        traceback.print_exc() # Print full traceback for debugging
    finally:
        # Ensure profiling is stopped and summary is attempted
        sys.setprofile(None)
        print("[Monitor] Profiling gestoppt (finally).")
        # atexit handler (print_summary) will run after this

# --- GUI Code --- #

# GUI: start monitoring subprocess
def start_monitor(script_path, text_widget, start_button, stop_button, marker_button, marker_a_file, marker_b_file, stop_file, results_file):
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'
    env['MONITOR_STOP_FILE'] = stop_file
    env['MONITOR_MARKER_A_FILE'] = marker_a_file
    env['MONITOR_MARKER_B_FILE'] = marker_b_file
    env['MONITOR_RESULTS_FILE'] = results_file # Pass results file path

    # Command to run the monitor part of this script
    cmd = [sys.executable, '-u', __file__, 'monitor', script_path]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=1, # Line buffered
            text=True,
            encoding='utf-8',
            errors='replace', # Replace undecodable characters
            env=env,
            # Set CWD for the subprocess? No, wrapper_main handles CWD change.
        )
    except Exception as e:
        messagebox.showerror("Fehler beim Start", f"Monitor-Prozess konnte nicht gestartet werden:\n{e}")
        return None

    start_button.config(state='disabled')
    stop_button.config(state='normal')
    marker_button.config(state='normal') # Enable marker button on start

    # Thread to read monitor output
    def reader():
        try:
            for line in process.stdout:
                if text_widget.winfo_exists(): # Check if widget still exists
                    text_widget.insert(tk.END, line)
                    text_widget.see(tk.END) # Auto-scroll
        except Exception as e:
            if text_widget.winfo_exists():
                 text_widget.insert(tk.END, f"\n[GUI] Fehler beim Lesen der Ausgabe: {e}\n")
        finally:
            if process.stdout:
                process.stdout.close()
            process.wait() # Wait for process to finish
            if text_widget.winfo_exists():
                start_button.config(state='normal')
                stop_button.config(state='disabled')
                marker_button.config(state='disabled') # Disable marker button on stop
                text_widget.insert(tk.END, "\n[GUI] Monitor-Prozess beendet.\n")
                text_widget.see(tk.END)
            # Clean up signal files (results file is kept for on_extract)
            for f in [stop_file, marker_a_file, marker_b_file]:
                if f and os.path.exists(f):
                    try: os.remove(f)
                    except OSError: pass

    threading.Thread(target=reader, daemon=True).start()
    return process

# GUI: signal monitor subprocess to stop
def signal_stop_monitor(process, stop_file):
    if process and process.poll() is None: # If process exists and is running
        print(f"[GUI] Sende Stop-Signal via Datei: {stop_file}")
        try:
            with open(stop_file, 'w') as f:
                f.write('stop') # Write something to the file
        except Exception as e:
             print(f"[GUI] Fehler beim Erstellen der Stop-Datei: {e}")

# GUI: signal monitor subprocess to set a marker
def signal_set_marker(marker_file):
     print(f"[GUI] Sende Marker-Signal via Datei: {marker_file}")
     try:
         with open(marker_file, 'w') as f:
             f.write('mark')
     except Exception as e:
          print(f"[GUI] Fehler beim Erstellen der Marker-Datei: {e}")

# Tkinter App class
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PyCallInspector")
        self.geometry("800x600")

        self.process = None
        # Define signal file paths based on PID
        self.pid = os.getpid()
        self.signal_dir = tempfile.gettempdir()
        self.stop_file = os.path.join(self.signal_dir, f"pycallinspector_{self.pid}.stop")
        self.marker_a_file = os.path.join(self.signal_dir, f"pycallinspector_{self.pid}.mark_a")
        self.marker_b_file = os.path.join(self.signal_dir, f"pycallinspector_{self.pid}.mark_b")
        self.results_file = os.path.join(self.signal_dir, f"pycallinspector_{self.pid}.results.json") # Results file

        self.marker_state = 'None' # 'None', 'A_Set', 'B_Set'
        self.last_monitored_script = None # Store path of last monitored script

        self.create_widgets()
        self.cleanup_signal_files() # Clean up any old files on startup

    def cleanup_signal_files(self):
        # Clean up signal files from potentially crashed previous runs
        for f in [self.stop_file, self.marker_a_file, self.marker_b_file, self.results_file]: # Include results file
             if f and os.path.exists(f):
                 try: os.remove(f)
                 except OSError: pass

    def create_widgets(self):
        # Top control frame
        frm = ttk.Frame(self)
        frm.pack(padx=10, pady=10, fill='x')
        frm.columnconfigure(1, weight=1) # Make entry expand

        ttk.Label(frm, text='Script Path:').grid(row=0, column=0, sticky='w', padx=(0, 5))
        self.path_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.path_var).grid(row=0, column=1, sticky='ew')
        ttk.Button(frm, text='Browse...', command=self.browse_file).grid(row=0, column=2, padx=5)

        # Button frame
        btn_frm = ttk.Frame(self)
        btn_frm.pack(padx=10, pady=(0, 10), fill='x')

        ttk.Button(btn_frm, text='Extract Definitions', command=self.on_extract).pack(side='left')
        ttk.Button(btn_frm, text='Show Hierarchy',    command=self.on_hierarchy).pack(side='left', padx=5)

        # Group Start/Marker/Stop buttons on the right
        self.btn_stop  = ttk.Button(btn_frm, text='Stop',  command=self.on_stop,  state='disabled')
        self.btn_stop.pack(side='right')
        self.btn_marker = ttk.Button(btn_frm, text='Set Marker A', command=self.on_set_marker, state='disabled')
        self.btn_marker.pack(side='right', padx=5)
        self.btn_start = ttk.Button(btn_frm, text='Start', command=self.on_start)
        self.btn_start.pack(side='right')

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
        self.def_frame = def_frame # Keep reference for notebook.select
        self.notebook.add(def_frame, text='Definitions')
        vscroll_def = ttk.Scrollbar(def_frame, orient='vertical')
        self.def_text = tk.Text(def_frame, wrap='none', yscrollcommand=vscroll_def.set)
        vscroll_def.config(command=self.def_text.yview)
        vscroll_def.pack(side='right', fill='y')
        self.def_text.pack(side='left', fill='both', expand=True)

        # Call Hierarchy tab
        hier_frame = ttk.Frame(self.notebook)
        self.hier_frame = hier_frame # Keep reference for notebook.select
        self.notebook.add(hier_frame, text='Hierarchie')
        vscroll_hier = ttk.Scrollbar(hier_frame, orient='vertical')
        self.hier_text = tk.Text(hier_frame, wrap='none', yscrollcommand=vscroll_hier.set)
        vscroll_hier.config(command=self.hier_text.yview)
        vscroll_hier.pack(side='right', fill='y')
        self.hier_text.pack(side='left', fill='both', expand=True)

        # Context menus for copy and select all
        self.monitor_menu = self.create_context_menu(self.text)
        self.text.bind('<Button-3>', lambda e: self.show_context_menu(e, self.monitor_menu))

        self.def_menu = self.create_context_menu(self.def_text)
        self.def_text.bind('<Button-3>', lambda e: self.show_context_menu(e, self.def_menu))

        self.hier_menu = self.create_context_menu(self.hier_text)
        self.hier_text.bind('<Button-3>', lambda e: self.show_context_menu(e, self.hier_menu))

        # Sizegrip for resizing
        sizegrip = ttk.Sizegrip(self)
        sizegrip.pack(side='bottom', anchor='se')

    # Create context menu with Copy and Select All
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

    # Method to select all text in a widget
    def select_all_text(self, widget):
        if not widget.winfo_exists(): return
        widget.tag_add(tk.SEL, "1.0", tk.END)
        widget.mark_set(tk.INSERT, "1.0")
        widget.see(tk.INSERT)
        return 'break' # Prevent default behavior

    def browse_file(self):
        path = filedialog.askopenfilename(filetypes=[('Python Files', '*.py'), ('All files', '*.*')])
        if path:
            self.path_var.set(os.path.abspath(path)) # Store absolute path

    def on_start(self):
        path = self.path_var.get()
        if not path or not os.path.isfile(path):
            messagebox.showerror('Error', 'Ungültige oder nicht existierende Script-Datei.')
            return

        # Stop previous process if running
        if self.process and self.process.poll() is None:
            signal_stop_monitor(self.process, self.stop_file)

        # Clean up signal files before starting new run
        self.cleanup_signal_files()

        # Reset marker state for the new run
        self.marker_state = 'None'
        self.btn_marker.config(text="Set Marker A", state='disabled') # Disabled until process starts

        # Clear previous output
        self.text.delete('1.0', tk.END)
        self.def_text.delete('1.0', tk.END)
        self.hier_text.delete('1.0', tk.END)

        # Store path for on_extract filtering
        self.last_monitored_script = path

        # Start the monitor process
        self.process = start_monitor(
            path,
            self.text,
            self.btn_start,
            self.btn_stop,
            self.btn_marker,
            self.marker_a_file,
            self.marker_b_file,
            self.stop_file,
            self.results_file # Pass results file path
        )
        if self.process: # If start was successful
             self.notebook.select(0) # Switch to monitor tab
        else: # Start failed
            self.btn_start.config(state='normal')
            self.btn_stop.config(state='disabled')
            self.btn_marker.config(state='disabled')
            self.last_monitored_script = None # Reset if start failed

    def on_stop(self):
        signal_stop_monitor(self.process, self.stop_file)

    def on_set_marker(self):
        if not self.process or self.process.poll() is not None:
            messagebox.showwarning("Marker", "Monitoring muss laufen, um Marker zu setzen.")
            return

        if self.marker_state == 'None':
            signal_set_marker(self.marker_a_file)
            self.marker_state = 'A_Set'
            self.btn_marker.config(text="Set Marker B")
            self.text.insert(tk.END, "\n[GUI] Marker A Signal gesendet.\n")
            self.text.see(tk.END)
        elif self.marker_state == 'A_Set':
            signal_set_marker(self.marker_b_file)
            self.marker_state = 'B_Set'
            self.btn_marker.config(text="Clear Markers")
            self.text.insert(tk.END, "\n[GUI] Marker B Signal gesendet.\n")
            self.text.see(tk.END)
        elif self.marker_state == 'B_Set':
            # Clear markers conceptually - remove signal files if they exist
            # Monitor won't use indices if they weren't set.
            if os.path.exists(self.marker_a_file):
                try: os.remove(self.marker_a_file)
                except OSError: pass
            if os.path.exists(self.marker_b_file):
                try: os.remove(self.marker_b_file)
                except OSError: pass
            # Also clear the results file so on_extract shows all defs again
            if os.path.exists(self.results_file):
                try: os.remove(self.results_file)
                except OSError: pass

            self.marker_state = 'None'
            self.btn_marker.config(text="Set Marker A")
            self.text.insert(tk.END, "\n[GUI] Marker gelöscht (lokaler Status & Ergebnisdatei zurückgesetzt).\n")
            self.text.see(tk.END)

    def on_extract(self):
        # Use the path from the last monitoring run if available, otherwise current path
        path = self.last_monitored_script if self.last_monitored_script else self.path_var.get()
        if not path or not os.path.isfile(path):
            messagebox.showerror('Error', 'Ungültige oder nicht existierende Script-Datei.')
            return

        called_funcs_filter = None
        try:
            # Try to load the filtered function list from the last run
            if os.path.exists(self.results_file):
                with open(self.results_file, 'r', encoding='utf-8') as f:
                    loaded_list = json.load(f)
                # Create a filter set of (name, line) for the *current* script path
                # Use absolute paths for comparison
                current_script_abs = os.path.abspath(path)
                called_funcs_filter = {(name, line) for name, pth, line in loaded_list if os.path.abspath(pth) == current_script_abs}
                print(f"[GUI] Filter für Definitionen geladen: {len(called_funcs_filter)} Funktionen für {current_script_abs}") # Debug
        except FileNotFoundError:
            pass # No results file, show all definitions
        except json.JSONDecodeError as e:
            print(f"[GUI] Fehler beim Lesen der Ergebnisdatei {self.results_file}: {e}")
            messagebox.showwarning("Filterfehler", f"Ergebnisdatei konnte nicht gelesen werden ({e}). Zeige alle Definitionen.")
        except Exception as e:
            print(f"[GUI] Unerwarteter Fehler beim Laden des Filters: {e}")
            messagebox.showwarning("Filterfehler", f"Unerwarteter Fehler beim Laden des Filters ({e}). Zeige alle Definitionen.")

        try:
            # Attempt to detect encoding, fall back to utf-8
            encoding = 'utf-8'
            try:
                import chardet
                with open(path, 'rb') as f_raw:
                    detected = chardet.detect(f_raw.read(4096))
                    if detected['encoding'] and detected['confidence'] > 0.7:
                        encoding = detected['encoding']
            except ImportError:
                pass
            except Exception:
                pass

            with open(path, 'r', encoding=encoding, errors='replace') as f:
                source = f.read()
            tree = ast.parse(source, filename=path)
            defs_to_show = []
            lines = source.splitlines()
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    name = node.name
                    lineno = node.lineno

                    # Apply filter if active
                    if called_funcs_filter is not None:
                        if (name, lineno) not in called_funcs_filter:
                            continue # Skip this definition if not in the filtered set

                    # Extract snippet
                    start = lineno - 1
                    end = getattr(node, 'end_lineno', None)
                    if end is None:
                        end = start + len(ast.unparse(node).splitlines())
                    snippet = '\n'.join(lines[start:end])
                    defs_to_show.append((name, lineno, snippet))

            self.def_text.delete('1.0', tk.END)
            if defs_to_show:
                defs_to_show.sort(key=lambda item: item[1]) # Sort by line number
                filter_active = called_funcs_filter is not None
                self.def_text.insert(tk.END, f"--- {len(defs_to_show)} Definitionen gefunden" + (" (gefiltert nach Marker-Aufrufen)" if filter_active else "") + " ---\n\n")
                for name, lineno, snippet in defs_to_show:
                    self.def_text.insert(tk.END, f"# --- Definition: {name} (Line: {lineno}) ---\n")
                    self.def_text.insert(tk.END, snippet + '\n\n')
            else:
                if called_funcs_filter is not None:
                    self.def_text.insert(tk.END, 'Keine der im markierten Bereich aufgerufenen Funktionen/Klassen gefunden.')
                else:
                    self.def_text.insert(tk.END, 'Keine Funktions- oder Klassendefinitionen gefunden.')

            self.notebook.select(self.def_frame) # Switch to definitions tab
        except Exception as e:
            messagebox.showerror('Fehler beim Extrahieren', f'Definitionen konnten nicht extrahiert werden:\n{e}')

    def on_hierarchy(self):
        try:
            content = self.text.get('1.0', tk.END).splitlines()
        except tk.TclError:
             messagebox.showerror("Fehler", "Monitor-Ausgabe konnte nicht gelesen werden.")
             return

        prefix = '🗂 Aufrufhierarchie'
        start_idx = -1
        for i, line in enumerate(content):
            if line.strip().startswith(prefix):
                start_idx = i + 1
                break

        self.hier_text.delete('1.0', tk.END)
        if start_idx == -1 or start_idx >= len(content):
            self.hier_text.insert(tk.END, 'Keine Aufrufhierarchie in der Monitor-Ausgabe gefunden.\nStelle sicher, dass das Monitoring beendet wurde.')
        else:
            found_hierarchy = False
            for line in content[start_idx:]:
                if line.startswith('[') and not line.startswith('[Monitor]'):
                     break
                if line.strip().startswith('-') or (line.startswith(' ') and line.lstrip().startswith('-')):
                    self.hier_text.insert(tk.END, line + '\n')
                    found_hierarchy = True
                elif found_hierarchy and not line.strip():
                    self.hier_text.insert(tk.END, line + '\n')
                elif found_hierarchy and line.strip():
                    break
            if not found_hierarchy:
                 self.hier_text.insert(tk.END, 'Keine Aufrufhierarchie-Zeilen nach dem Header gefunden.')

        self.notebook.select(self.hier_frame) # Switch to hierarchy tab

    def on_closing(self):
        if self.process and self.process.poll() is None:
            signal_stop_monitor(self.process, self.stop_file)
        self.cleanup_signal_files()
        self.destroy()

# --- Main Execution --- #
if __name__ == '__main__':
    # Check if running in monitor mode (subprocess)
    if len(sys.argv) > 1 and sys.argv[1] == 'monitor':
        if len(sys.argv) < 3:
            print('Usage: python pycallinspector.py monitor <script_to_monitor.py> [script_args...]')
            sys.exit(1)
        target_script_path = sys.argv[2]
        wrapper_main(target_script_path)
    else:
        # Run the GUI application
        app = App()
        app.protocol('WM_DELETE_WINDOW', app.on_closing) # Handle window close button
        app.mainloop()

