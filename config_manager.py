from pathlib import Path
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime

from i18n import t
import settings
from validators import is_valid_hostname_or_ip

# Paths de configuración
CONFIG_PATH = settings.SSH_CONFIG_PATH
BACKUP_DIR = settings.BACKUP_DIR


def load_config():
    """
    Parsea el archivo SSH config y devuelve una lista de hosts.
    """
    hosts = []
    current = {}
    if not CONFIG_PATH.exists():
        return []

    with CONFIG_PATH.open("r", encoding="utf-8") as f:
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
                else:
                    # Línea malformada en ~/.ssh/config: advertencia al usuario
                    messagebox.showwarning(
                        t("error"),
                        f"Línea ignorada en ~/.ssh/config: '{line}'"
                    )
        if current:
            hosts.append(current)
    return hosts


def write_config(hosts):
    """
    Guarda la lista de hosts, haciendo backup previo del archivo original.
    """
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    if CONFIG_PATH.exists() and CONFIG_PATH.stat().st_size > 0:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        backup_path = BACKUP_DIR / f"config.backup-{timestamp}"
        try:
            shutil.copy(str(CONFIG_PATH), str(backup_path))
        except Exception as e:
            print(t("error_backup").format(e=e))

    with CONFIG_PATH.open("w", encoding="utf-8") as f:
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
    """
    Permite al usuario seleccionar y restaurar una copia de seguridad.
    """
    if not BACKUP_DIR.is_dir():
        return False

    path_str = filedialog.askopenfilename(
        initialdir=str(BACKUP_DIR),
        title=t("selecciona_backup"),
        filetypes=[(t("backups_ssh"), "config.backup-*"), (t("todos_los_archivos"), "*.*")]
    )
    if not path_str:
        return False
    path = Path(path_str)

    confirm = messagebox.askyesno(t("restaurar_backup"), t("confirmar_restauracion").format(path=path))
    if not confirm:
        return False

    try:
        shutil.copy(str(path), str(CONFIG_PATH))
        return True
    except Exception as e:
        messagebox.showerror(t("error"), t("no_backup_restaurado").format(e=e))
        return False
