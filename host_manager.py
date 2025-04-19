import tkinter as tk
from tkinter import messagebox
import subprocess
from auth import (
    store_password_in_pass,
    delete_password_from_pass,
    get_password_from_pass
)
from i18n import t
from config_manager import is_valid_hostname_or_ip
from gui import toggle_password

def validar_host_campos(fields, identity_text):
    host_name = fields[t("hostname")].get().strip()
    port = fields["Port"].get().strip()

    if host_name and not is_valid_hostname_or_ip(host_name):
        messagebox.showerror(t("error"), t("hostname_invalido").format(host_name=host_name))
        return None

    if port and not port.isdigit():
        messagebox.showerror(t("error"), t("puerto_entero").format(port=port))
        return None

    data = {key: entry.get().strip() for key, entry in fields.items() if entry.get().strip()}
    identity_files = identity_text.get("1.0", tk.END).strip().splitlines()
    if identity_files:
        data[t("identityfile")] = identity_files

    if not data.get("Host"):
        messagebox.showerror(t("error"), t("campo_host_obligatorio"))
        return None

    return data

def manejar_password(hostname, password_value):
    pass_key = f"sshConfigGUI/host-{hostname}/password"
    if password_value:
        store_password_in_pass(pass_key, password_value)
    else:
        delete_password_from_pass(pass_key)

def eliminar_password_por_host(hostname):
    pass_key = f"sshConfigGUI/host-{hostname}/password"
    delete_password_from_pass(pass_key)

def limpiar_campos_host(app):
    for entry in app.fields.values():
        entry.delete(0, tk.END)
    app.identityfile_text.delete("1.0", tk.END)
    app.password_entry.delete(0, tk.END)
    if app.password_shown:
        toggle_password(app)

def cargar_datos_host(app):
    host = app.hosts[app.selected_index]
    for key, entry in app.fields.items():
        entry.delete(0, tk.END)
        entry.insert(0, host.get(key, ""))
    app.identityfile_text.delete("1.0", tk.END)
    identity_files = host.get(t("identityfile"), [])
    if isinstance(identity_files, str):
        identity_files = [identity_files]
    app.identityfile_text.insert(tk.END, "\n".join(identity_files))
    app.password_entry.delete(0, tk.END)
    if host.get("Host"):
        pass_key = f"sshConfigGUI/host-{host['Host']}/password"
        try:
            password = get_password_from_pass(pass_key)
        except subprocess.CalledProcessError:
            password = ""
        app.password_entry.insert(0, password)
    if app.password_shown:
        toggle_password(app)