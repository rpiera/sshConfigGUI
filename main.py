import os
import re
import subprocess
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
import shutil

from config_manager import (
    load_config,
    write_config,
    restore_backup,
    is_valid_hostname_or_ip
)
from auth import (
    ensure_pass_ready,
    get_password_from_pass,
    store_password_in_pass,
    delete_password_from_pass
)
from gui import build_gui, toggle_password
from host_manager import (
    validar_host_campos,
    manejar_password,
    eliminar_password_por_host,
    limpiar_campos_host,
    cargar_datos_host
)

CONFIG_PATH = os.path.expanduser("~/.ssh/config")
PASS_ENTRY = "sshConfigGUI/master-password"


import json

APP_CONFIG_PATH = os.path.expanduser("~/.config/sshConfigGUI/settings.json")

class SSHConfigManager:
    def __init__(self, root):
        self._load_app_settings()
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *args: self.refresh_list_with_search())
        self.root = root
        self.root.title("SSH Config Manager")
        self.root.geometry(self.app_settings.get("window_size", "900x500"))
        self.hosts = []
        self.selected_index = None

        self.extra_fields = ["ProxyJump", "LocalForward", "RemoteForward", "ServerAliveInterval"]
        self.identity_shown = False
        self.password_shown = False

        ensure_pass_ready()
        self.authenticate()

    def authenticate(self):
        pw_actual = get_password_from_pass()
        if pw_actual is None:
            nueva = simpledialog.askstring("Crear contraseña", "Establece una contraseña para la aplicación:", show='*')
            if nueva:
                store_password_in_pass(PASS_ENTRY, nueva)
                self.status_label = tk.Label(self.root, text="✅ Contraseña guardada en pass", fg="green")
                self.status_label.pack()
            else:
                messagebox.showerror("Cancelado", "No se ha establecido contraseña.")
                self.root.destroy()
                return
        else:
            pw = simpledialog.askstring("Acceso protegido", "Introduce la contraseña:", show='*')
            if pw != pw_actual:
                messagebox.showerror("Acceso denegado", "Contraseña incorrecta.")
                self.root.destroy()
                return

        build_gui(self, self.extra_fields)
        self.load_config()

    def restore_backup(self):
        if restore_backup():
            confirm = messagebox.askyesno("Restaurar backup", "¿Deseas restaurar la última copia de seguridad?")
            if confirm:
                self.load_config()
                messagebox.showinfo("Restaurado", "Backup restaurado correctamente.")
                self.status_label.config(text="✅ Backup restaurado")
        else:
            messagebox.showerror("Error", "No se encontró un archivo de backup para restaurar.")
            self.status_label.config(text="")

    def save_host(self):
        data = validar_host_campos(self.fields, self.identityfile_text)
        if not data:
            return

        if self.selected_index is not None:
            self.hosts[self.selected_index] = data
        else:
            self.hosts.append(data)

        pwd_value = self.password_entry.get().strip()
        manejar_password(data['Host'], pwd_value)

        write_config(self.hosts)
        self.refresh_list_with_search()
        self.status_label.config(text="✅ Cambios guardados")

    def delete_host(self):
        if self.selected_index is not None:
            confirm = messagebox.askyesno("Confirmar eliminación", "¿Estás seguro de que quieres eliminar este host?")
            if confirm:
                host_alias = self.hosts[self.selected_index].get("Host")
                del self.hosts[self.selected_index]
                self.selected_index = None
                write_config(self.hosts)
                self.refresh_list_with_search()
                limpiar_campos_host(self)
                if host_alias:
                    eliminar_password_por_host(host_alias)
                self.status_label.config(text="✅ Host eliminado")

    def new_host(self):
        limpiar_campos_host(self)
        self.selected_index = None
        self.status_label.config(text="")

    def _load_app_settings(self):
        try:
            with open(APP_CONFIG_PATH, "r", encoding="utf-8") as f:
                self.app_settings = json.load(f)
        except Exception:
            self.app_settings = {}

    def _save_app_settings(self):
        self.app_settings["window_size"] = self.root.winfo_geometry()
        if self.selected_index is not None and 0 <= self.selected_index < len(self.filtered_hosts):
            self.app_settings["last_host"] = self.filtered_hosts[self.selected_index].get("Host")
        self.app_settings["password_shown"] = self.password_shown
        os.makedirs(os.path.dirname(APP_CONFIG_PATH), exist_ok=True)
        with open(APP_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(self.app_settings, f, indent=2)

    def load_config(self):
        self.hosts = load_config()
        self.refresh_list_with_search()

    def is_valid_hostname_or_ip(self, value):
        return is_valid_hostname_or_ip(value)

    def refresh_list_with_search(self):
        last_host = self.app_settings.get("last_host")
        select_index = None
        query = self.search_var.get().strip().lower()
        filtered = [h for h in self.hosts if query in h.get("Host", "").lower()]
        self.filtered_hosts = filtered
        self.selected_index = None
        self.host_listbox.delete(0, tk.END)
        for i, host in enumerate(filtered):
            name = host.get("Host", "")
            self.host_listbox.insert(tk.END, name)
            if name == last_host:
                select_index = i

    def copy_ssh_command(self):
        if self.selected_index is not None and self.selected_index < len(self.filtered_hosts):
            host = self.filtered_hosts[self.selected_index]
            user = host.get("User", "")
            hostname = host.get("HostName", "")
            port = host.get("Port", "")
            if hostname:
                cmd = "ssh"
                if user:
                    cmd += f" {user}@{hostname}"
                else:
                    cmd += f" {hostname}"
                if port:
                    cmd += f" -p {port}"
                try:
                    self.root.clipboard_clear()
                    self.root.clipboard_append(cmd)
                    self.root.update()
                    self.status_label.config(text="✅ Copiado al portapapeles")
                except Exception as e:
                    messagebox.showerror("Error", f"No se pudo copiar al portapapeles: {e}")
            else:
                messagebox.showwarning("Campo incompleto", "Este host no tiene 'HostName'.")
        else:
            messagebox.showwarning("Sin selección", "Selecciona un host para copiar su comando SSH.")

    def select_identity_file(self):
        path = filedialog.askopenfilename(
            title="Seleccionar archivo de clave SSH",
            filetypes=[
                ("Archivos de clave", "*.pem *.key *.pub *.id_rsa *"),
                ("Todos los archivos", "*.*")
            ]
        )
        if path:
            current = self.identityfile_text.get("1.0", tk.END).strip()
            lines = current.splitlines() if current else []
            if path not in lines:
                lines.append(path)
            self.identityfile_text.delete("1.0", tk.END)
            self.identityfile_text.insert(tk.END, "".join(lines))

            if select_index is not None:
                self.host_listbox.select_set(select_index)
                self.host_listbox.event_generate("<<ListboxSelect>>")

    def write_config(self):
        write_config(self.hosts)


if __name__ == "__main__":
    root = tk.Tk()
    app = SSHConfigManager(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app._save_app_settings(), root.destroy()))
    root.mainloop()

