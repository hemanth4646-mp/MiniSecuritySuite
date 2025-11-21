# Mini Security Suite

Small demo bundle with three utilities:

- Password strength checker (`password_checker.py`)
- Simple encrypt/decrypt demo (`encryption_tool.py`)
- Basic IDS that prints CPU alerts and established remote connections (`intrusion_detection.py`)

## Requirements

- Python 3.8+ recommended
- Dependencies listed in `requirements.txt` (cryptography, psutil)

## Install

Open PowerShell and run:

```powershell
python -m pip install -r "C:\Users\Hemanth Kumar MP\Desktop\MiniSecuritySuite\requirements.txt"
```

## Run

Start the main menu:

```powershell
python "C:\Users\Hemanth Kumar MP\Desktop\MiniSecuritySuite\main.py"
```

## Usage notes

- Menu choices are interactive. After a task completes you'll be asked whether to perform another.
- Option: "Run Basic IDS" runs a short default check (3 iterations) and returns to the menu.
- Continuous IDS (if started) runs until you press Ctrl+C.
- The encryption demo generates a new, in-memory key each run (not persisted). If you need persistent keys, modify `encryption_tool.py` to save/load a key file.

## Developing / Testing

- Quick syntax check:

```powershell
python -m py_compile "C:\Users\Hemanth Kumar MP\Desktop\MiniSecuritySuite\*.py"
```

- To run a single IDS check during development:

```powershell
python -c "from intrusion_detection import basic_ids; basic_ids(max_checks=1, interval=0.1, sleep_between=0.1)"
```

## Notes

This project is a lightweight demo. The IDS is synchronous and intended for demonstration only; for production use run monitoring in a background thread/process and add proper logging and filtering.
