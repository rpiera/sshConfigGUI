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
from gui import build_gui, refresh_listbox, toggle_password
from host_manager import (
    validar_host_campos,
    manejar_password,
    eliminar_password_por_host,
    limpiar_campos_host,
    cargar_datos_host
)

CONFIG_PATH = os.path.expanduser("~/.ssh/config")
PASS_ENTRY = "sshConfigGUI/master-password"

class SSHConfigManager:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Config Manager")
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
        refresh_listbox(self)
        self.status_label.config(text="✅ Cambios guardados")

    def delete_host(self):
        if self.selected_index is not None:
            confirm = messagebox.askyesno("Confirmar eliminación", "¿Estás seguro de que quieres eliminar este host?")
            if confirm:
                host_alias = self.hosts[self.selected_index].get("Host")
                del self.hosts[self.selected_index]
                self.selected_index = None
                write_config(self.hosts)
                refresh_listbox(self)
                limpiar_campos_host(self)
                if host_alias:
                    eliminar_password_por_host(host_alias)
                self.status_label.config(text="✅ Host eliminado")

    def new_host(self):
        limpiar_campos_host(self)
        self.selected_index = None
        self.status_label.config(text="")

    def load_config(self):
        self.hosts = load_config()
        refresh_listbox(self)

    def is_valid_hostname_or_ip(self, value):
        return is_valid_hostname_or_ip(value)

    def write_config(self):
        write_config(self.hosts)

if __name__ == "__main__":
    root = tk.Tk()
    app = SSHConfigManager(root)
    root.mainloop()
