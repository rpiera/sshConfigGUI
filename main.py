import os
import re
import subprocess
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
import shutil
import sys
import json
from datetime import datetime

from config_manager import (
    load_config,
    write_config,
    restore_backup,
    is_valid_hostname_or_ip
)

from i18n import load_language, t
load_language("es")

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
APP_CONFIG_PATH = os.path.expanduser("~/.config/sshConfigGUI/settings.json")


class SSHConfigManager:
    readonly = False

    def __init__(self, root):
        self._last_config_mtime = 0
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
            nueva = simpledialog.askstring(t("crear_contrasena"), t("establece_contrasena"), show='*')
            if nueva:
                store_password_in_pass(PASS_ENTRY, nueva)
                self.status_label = tk.Label(self.root, text=t("contrasena_guardada"), fg="green")
                self.status_label.pack()
            else:
                messagebox.showerror(t("cancelado"), t("no_contrasena"))
                self.root.destroy()
                return
        else:
            pw = simpledialog.askstring(t("acceso_protegido"), t("introduce_contrasena"), show='*')
            if pw != pw_actual:
                messagebox.showerror(t("acceso_denegado"), t("contrasena_incorrecta"))
                self.root.destroy()
                return

        build_gui(self, self.extra_fields)
        self._add_readonly_toggle()
        self.load_config()

    def restore_backup(self):
        if restore_backup():
            self.load_config()
            messagebox.showinfo(t("restaurado"), t("backup_restaurado"))
            self.status_label.config(text=t("backup_restaurado_status"))
        else:
            messagebox.showerror(t("error"), t("no_backup"))
            self.status_label.config(text="")

    def save_host(self):
        if self.readonly:
            messagebox.showinfo(t("solo_lectura"), t("solo_lectura_msg"))
            return

        data = validar_host_campos(self.fields, self.identityfile_text)
        if not data:
            return

        if self.selected_index is not None:
            existing_hosts = [h.get("Host", "") for i, h in enumerate(self.hosts) if i != self.selected_index]
            if data["Host"] in existing_hosts:
                messagebox.showwarning(t("duplicado"), t("host_duplicado") + f" '{data['Host']}'.")
                return
            self.hosts[self.selected_index] = data
        else:
            existing_hosts = [h.get("Host", "") for h in self.hosts]
            if data["Host"] in existing_hosts:
                messagebox.showwarning(t("duplicado"), t("host_duplicado") + f" '{data['Host']}'.")
                return
            self.hosts.append(data)

        pwd_value = self.password_entry.get().strip()
        manejar_password(data['Host'], pwd_value)

        write_config(self.hosts)
        self.refresh_list_with_search()
        self.status_label.config(text=t("cambios_guardados"))

    def delete_host(self):
        if self.readonly:
            messagebox.showinfo(t("solo_lectura"), "No puedes eliminar en modo de solo lectura.")
            return
        if self.selected_index is not None:
            confirm = messagebox.askyesno(t("confirmar_eliminacion"), t("confirmar_eliminacion_msg"))
            if confirm:
                host_alias = self.hosts[self.selected_index].get("Host")
                del self.hosts[self.selected_index]
                self.selected_index = None
                write_config(self.hosts)
                self.refresh_list_with_search()
                limpiar_campos_host(self)
                if host_alias:
                    eliminar_password_por_host(host_alias)
                self.status_label.config(text=t("host_eliminado"))

    def new_host(self):
        if self.readonly:
            messagebox.showinfo(t("solo_lectura"), "No puedes crear un host nuevo en modo de solo lectura.")
            return
        limpiar_campos_host(self)
        self.selected_index = None
        self.status_label.config(text="")

    def _add_readonly_toggle(self):
        # Selector de idioma
        lang_frame = tk.Frame(self.root)
        lang_frame.pack(fill=tk.X, pady=(2, 0))
        tk.Label(lang_frame, text=t("idioma")).pack(side=tk.LEFT, padx=(10, 4))
        self.lang_var = tk.StringVar(value=self.app_settings.get("lang", "en"))
        lang_select = tk.OptionMenu(lang_frame, self.lang_var, "es", "en", command=self._change_language)
        lang_select.pack(side=tk.LEFT)
        toggle_frame = tk.Frame(self.root)
        toggle_frame.pack(fill=tk.X, pady=(2, 0))
        self.readonly_var = tk.BooleanVar(value=self.readonly)
        readonly_btn = tk.Checkbutton(toggle_frame, text=t("modo_solo_lectura"), variable=self.readonly_var,
                                      command=self._toggle_readonly)
        readonly_btn.pack(anchor="w", padx=10)

    def _change_language(self, selected):
        self.app_settings["lang"] = selected
        load_language(selected)
        self._save_app_settings()
        self.root.destroy()
        os.execl(sys.executable, sys.executable, *sys.argv)

    def _toggle_readonly(self):
        self.readonly = self.readonly_var.get()
        estado = "activado" if self.readonly else "desactivado"
        self.status_label.config(text=f"🔒 Modo solo lectura {estado}")

        state = tk.DISABLED if self.readonly else tk.NORMAL
        for entry in self.fields.values():
            entry.config(state=state)
        self.identityfile_text.config(state=state)
        self.password_entry.config(state=state)
        if hasattr(self, 'add_identity_button'):
            self.add_identity_button.config(state=state)

    def _load_app_settings(self):
        self.readonly = False
        try:
            with open(APP_CONFIG_PATH, "r", encoding="utf-8") as f:
                self.app_settings = json.load(f)
                self.readonly = self.app_settings.get("readonly", False)
                lang = self.app_settings.get("lang", "en")
                load_language(lang)
        except Exception:
            self.app_settings = {}

    def _save_app_settings(self):
        self.app_settings["window_size"] = self.root.winfo_geometry()
        if self.selected_index is not None and 0 <= self.selected_index < len(self.filtered_hosts):
            self.app_settings["last_host"] = self.filtered_hosts[self.selected_index].get("Host")
        self.app_settings["password_shown"] = self.password_shown
        self.app_settings["readonly"] = self.readonly
        self.app_settings["lang"] = self.app_settings.get("lang", "en")
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

        if select_index is not None:
            self.host_listbox.select_set(select_index)
            self.host_listbox.event_generate("<<ListboxSelect>>")

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
                    messagebox.showerror(t("error"), f"No se pudo copiar al portapapeles: {e}")
            else:
                messagebox.showwarning(t("campo_incompleto"), t("no_hostname"))
        else:
            messagebox.showwarning(t("sin_seleccion"), t("selecciona_para_copiar"))

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
            self.identityfile_text.insert(tk.END, "".join(lines))  # revisar cada 3s

    def test_ssh_connection(self):
        if self.selected_index is None or self.selected_index >= len(self.filtered_hosts):
            messagebox.showwarning(t("sin_seleccion"), t("selecciona_para_probar"))
            return

        host = self.filtered_hosts[self.selected_index]
        user = host.get("User", "")
        hostname = host.get("HostName", "")
        port = host.get("Port", "")
        if not hostname:
            messagebox.showerror(t("datos_incompletos"), t("no_hostname"))
            return

        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]
        if port:
            cmd.extend(["-p", port])
        target = f"{user}@{hostname}" if user else hostname
        cmd.append(target)
        cmd.append("exit")

        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=7)
            if result.returncode == 0:
                messagebox.showinfo("Conexión exitosa", f"✅ Conexión SSH a {target} verificada.")
            else:
                messagebox.showerror("Fallo en conexión",
                                     f"No se pudo conectar a {target}:{result.stderr.decode().strip()}")
        except Exception as e:
            messagebox.showerror(t("error"), f"Error al ejecutar SSH:{str(e)}")

    def export_hosts_to_json(self):
        path = filedialog.asksaveasfilename(
            title="Exportar hosts como JSON",
            defaultextension=".json",
            filetypes=[("Archivos JSON", "*.json")]
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self.hosts, f, indent=2)
                messagebox.showinfo("Exportación completa", f"Se exportaron los hosts a {path}.")
            except Exception as e:
                messagebox.showerror("Error al exportar", str(e))

    def import_hosts_from_json(self):
        path = filedialog.askopenfilename(
            title="Importar hosts desde JSON",
            filetypes=[("Archivos JSON", "*.json")]
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if not isinstance(data, list):
                        raise ValueError("El archivo JSON debe contener una lista de hosts.")
                    confirm = messagebox.askyesno("Confirmar importación",
                                                  "¿Deseas reemplazar todos los hosts actuales?")
                    if confirm:
                        self.hosts = data
                        write_config(self.hosts)
                        self.refresh_list_with_search()
                        messagebox.showinfo("Importación completada", f"Se importaron {len(data)} hosts desde {path}.")
            except Exception as e:
                messagebox.showerror("Error al importar", str(e))

    def write_config(self):
        write_config(self.hosts)


if __name__ == "__main__":
    root = tk.Tk()
    app = SSHConfigManager(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (
        app._save_app_settings(),
        root.destroy()
    ))
    root.mainloop()
