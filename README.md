# PyCallInspector

PyCallInspector is a cross-platform tool for monitoring and profiling Python scripts. It captures and lists all function calls in your own `.py` files (excluding standard library and site-packages), providing a clear summary at the end of execution or upon manual stop.

## Features

- **Function Call Tracing**  
  Captures every function call in your project files during script execution.

- **Detailed Summary**  
  Outputs a sorted list of called functions with file paths and line numbers.

- **Graceful Stop**  
  - **Unix/Linux/macOS**: Clean interruption via `SIGINT`/`SIGTERM`.  
  - **Windows**: Stop-file watcher signals a clean shutdown.

- **GUI and CLI Modes**  
  - **GUI**: Simple Tkinter interface with file picker, live log view, and Start/Stop controls.  
  - **CLI**: Run headless in terminal.

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

## Example Output

```
[Monitor Process] Running target script: example.py with args: ['example.py']
[Monitor Process] Signal 2 received. Setting stop flag for main thread...

🧠 Aufgerufene Funktionen (aus eigenen .py-Dateien):
 - <module>()        @ example.py:1
 - process_data()    @ example.py:42
 - save_results()    @ example.py:88
```

## Contributing

1. Fork the repo.  
2. Create a branch (`git checkout -b feature/...`).  
3. Commit and push.  
4. Open a Pull Request.

## License

MIT License—see [LICENSE](LICENSE).
