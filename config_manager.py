import os
import shutil
import json
from datetime import datetime

import tkinter as tk
from tkinter import filedialog, messagebox

CONFIG_PATH = os.path.expanduser("~/.ssh/config")


def load_config():
    hosts = []
    current = {}
    if not os.path.exists(CONFIG_PATH):
        return []
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                if current:
                    hosts.append(current)
                    current = {}
                continue
            if line.startswith("Host "):
                current["Host"] = line.split(" ", 1)[1]
            else:
                parts = line.split(" ", 1)
                if len(parts) == 2:
                    key, value = parts
                    if key == "IdentityFile":
                        current.setdefault("IdentityFile", []).append(value)
                    else:
                        current[key] = value
        if current:
            hosts.append(current)
    return hosts


def write_config(hosts):
    # Crear carpeta de backups
    backup_dir = os.path.expanduser("~/.config/sshConfigGUI/backups")
    os.makedirs(backup_dir, exist_ok=True)

    # Si existe el archivo actual, crear copia con timestamp
    if os.path.exists(CONFIG_PATH) and os.path.getsize(CONFIG_PATH) > 0:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        backup_path = os.path.join(backup_dir, f"config.backup-{timestamp}")
        try:
            shutil.copy(CONFIG_PATH, backup_path)
        except Exception as e:
            print(f"⚠️ No se pudo crear backup con timestamp: {e}")

    # Escribir nueva configuración
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        for host in hosts:
            f.write(f"Host {host.get('Host')}\n")
            for key, value in host.items():
                if key == "Host" or not value:
                    continue
                if key == "IdentityFile" and isinstance(value, list):
                    for path in value:
                        f.write(f"    IdentityFile {path}\n")
                else:
                    f.write(f"    {key} {value}\n")
            f.write("\n")


def restore_backup():
    backup_dir = os.path.expanduser("~/.config/sshConfigGUI/backups")
    if not os.path.isdir(backup_dir):
        return False

    root = tk.Tk()
    root.withdraw()

    path = filedialog.askopenfilename(
        initialdir=backup_dir,
        title="Selecciona un backup para restaurar",
        filetypes=[("Backups de SSH", "config.backup-*"), ("Todos los archivos", "*.*")]
    )

    if path:
        confirm = messagebox.askyesno("Restaurar backup", f"¿Deseas restaurar este archivo?\n\n{path}")
        if confirm:
            try:
                shutil.copy(path, CONFIG_PATH)
                return True
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo restaurar el backup:\n{e}")
                return False
    return False


def is_valid_hostname_or_ip(value):
    import re
    if not value:
        return False
    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    hostname_pattern = r"^[a-zA-Z0-9.-]+$"
    return re.match(ip_pattern, value) or re.match(hostname_pattern, value)
