# PyCallInspector

PyCallInspector is a cross-platform tool for monitoring and profiling Python scripts. It captures and lists all function calls in your own `.py` files (excluding standard library and site-packages), providing a clear summary at the end of execution or upon manual stop.

## Features

- **Function Call Tracing**  
  Captures every function call in your project files during script execution.

- **Detailed Summary & Hierarchy**  
  Outputs a sorted list of called functions and a call hierarchy tree with file paths and line numbers.

- **`<genexpr>` Filtering**
  Automatically filters out repetitive calls to internal generator expressions (`<genexpr>`) from the summary and hierarchy views for better readability.

- **Graceful Stop**  
  - **Unix/Linux/macOS**: Clean interruption via `SIGINT`/`SIGTERM`.
  - **Windows**: Stop-file watcher signals a clean shutdown.

- **GUI and CLI Modes**  
  - **GUI**: Simple Tkinter interface with file picker, live log view, Start/Stop controls, and context menus.
  - **CLI**: Run headless in terminal.

- **Context Menu Actions**
  Right-click menus in the GUI provide options like "Copy" and "Select All" for easy text handling.

## Requirements

- **Python 3.6+** (includes `tkinter` on most distributions)
- No additional pip packages required.

## Usage

### CLI Mode

```bash
python pycallinspector.py monitor your_script.py
```

Stop early with:
- **Linux/macOS**: `Ctrl+C`
- **Windows**: Use the GUI or remove the stop file (in temp dir).

### GUI Mode

```bash
python pycallinspector.py
```

1. **Browse**: Select the target `.py` file.
2. **Start**: Begin profiling.
3. **Stop**: Interrupt and display the summary.
4. **Right-click**: Use context menus in output areas for Copy/Select All.

## Known Limitations

- **Compiled Binary (.exe) Issues**: Currently, running PyCallInspector as a compiled executable (e.g., created with PyInstaller) has known limitations. Specifically, it may fail to monitor target scripts that import standard Python libraries (like `json`, `os`, etc.), often resulting in `ModuleNotFoundError`. This seems to be caused by complex interactions between Python's profiling mechanisms (`sys.setprofile`), the way the target script is executed (`runpy`), and how PyInstaller bundles libraries for subprocesses.
- **Recommendation**: For reliable monitoring, especially of scripts with various imports, it is **strongly recommended to run PyCallInspector directly from its source code** (`python pycallinspector.py`) rather than as a compiled binary until a robust solution for the binary version is found.

## Example Output (Filtered)

```
[Monitor] Starte example.py mit args: ["example.py"]
Starting test target...
Test target finished.
[Monitor] Ziel-Skript normal beendet.
[Monitor] Profiling gestoppt.

🧠 Aufgerufene Funktionen (aus eigenen .py-Dateien):
 - <module>()  @ example.py:1
 - frequently_called()  @ example.py:4
 - main()  @ example.py:11

🗂 Aufrufhierarchie:
- <module>()  @ example.py:1
  - main()  @ example.py:11
    - frequently_called()  @ example.py:4
    - frequently_called()  @ example.py:4
    - frequently_called()  @ example.py:4
```
(Note: `<genexpr>` calls are automatically filtered out)

## Contributing

1. Fork the repo.
2. Create a branch (`git checkout -b feature/...`).
3. Commit and push.
4. Open a Pull Request.

## License

MIT License—see [LICENSE](LICENSE).

