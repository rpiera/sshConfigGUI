import json
import subprocess
from tkinter import messagebox, filedialog
from typing import Optional, List

from models import Host
from config_manager import load_config, write_config, restore_backup
from auth import AuthService
import validators
from i18n import t


class SSHConfigController:
    """
    Controlador principal que coordina la vista, el modelo y los servicios.
    """
    def __init__(self, view):
        self.view = view
        self.auth = AuthService()
        self.auth.ensure_ready()
        self.hosts: List[Host] = []
        self.selected_index: Optional[int] = None

        # Cargar datos e inicializar la vista
        self.load_hosts()
        self._bind_view_events()

    def _bind_view_events(self):
        # Asociar callbacks de la vista a métodos del controlador
        self.view.on_new(self.new_host)
        self.view.on_save(self.save_host)
        self.view.on_delete(self.delete_host)
        self.view.on_restore(self.restore_backup)
        self.view.on_search(self.search_hosts)
        self.view.on_select(self.select_host)
        self.view.on_copy(self.copy_ssh_command)
        self.view.on_test(self.test_ssh_connection)
        self.view.on_export(self.export_hosts)
        self.view.on_import(self.import_hosts)
        # Callbacks de idioma y modo solo lectura
        self.view.on_language_change(self.change_language)
        self.view.on_toggle_readonly(self.toggle_readonly)

    def load_hosts(self):
        raw = load_config()
        self.hosts = [Host.from_dict(d) for d in raw]
        self.view.update_host_list(self.hosts)

    def new_host(self):
        self.selected_index = None
        self.view.clear_fields()

    def select_host(self, index: Optional[int]):
        # Ignorar si no hay selección válida
        if index is None:
            return
        self.selected_index = index
        host = self.hosts[index]
        # Rellenar campos en la vista
        self.view.populate_fields(host)
        # Precargar contraseña si existe
        entry = f"sshConfigGUI/host-{host.alias}/password"
        pwd = self.auth.get_password(entry)
        self.view.set_password(pwd)

    def save_host(self):
        data = self.view.get_form_data()
        if data is None:
            return

        # Validaciones
        alias = data.get('Host', '').strip()
        if not alias:
            messagebox.showerror(t("error"), t("campo_host_obligatorio"))
            return
        if not validators.is_valid_hostname_or_ip(alias):
            messagebox.showerror(t("error"), t("hostname_invalido").format(host_name=alias))
            return
        port = data.get('Port')
        if port and not validators.is_valid_port(port):
            messagebox.showerror(t("error"), t("puerto_entero").format(port=port))
            return
        if validators.detect_duplicate_alias(self.hosts, alias, exclude_index=self.selected_index):
            messagebox.showwarning(t("duplicado"), t("host_duplicado") + f" '{alias}'.")
            return

        # Crear o actualizar Host
        host = Host.from_dict(data)
        if self.selected_index is None:
            self.hosts.append(host)
        else:
            self.hosts[self.selected_index] = host

        # Gestionar contraseña
        entry = f"sshConfigGUI/host-{host.alias}/password"
        if data.get('ClearPassword'):
            self.auth.delete_password(entry)
        elif 'Password' in data:
            pwd = data['Password']
            self.auth.store_password(entry, pwd)

        # Guardar en config file
        dicts = [h.to_dict() for h in self.hosts]
        write_config(dicts)
        self.view.update_host_list(self.hosts)
        self.view.show_status(t("cambios_guardados"))

    def delete_host(self):
        if self.selected_index is None:
            return
        confirm = messagebox.askyesno(t("confirmar_eliminacion"), t("confirmar_eliminacion_msg"))
        if not confirm:
            return
        alias = self.hosts[self.selected_index].alias
        del self.hosts[self.selected_index]
        # Eliminar password
        entry = f"sshConfigGUI/host-{alias}/password"
        self.auth.delete_password(entry)
        # Reescribir config
        dicts = [h.to_dict() for h in self.hosts]
        write_config(dicts)
        self.view.update_host_list(self.hosts)
        self.view.clear_fields()
        self.view.show_status(t("host_eliminado"))

    def restore_backup(self):
        if restore_backup():
            self.load_hosts()
            self.view.show_info(t("restaurado"), t("backup_restaurado"))
        else:
            self.view.show_error(t("error"), t("no_backup"))

    def search_hosts(self, query: str):
        filtered = [h for h in self.hosts if query.lower() in h.alias.lower()]
        self.view.update_host_list(filtered)

    def copy_ssh_command(self):
        host = self.current_selected()
        if not host or not host.host_name:
            messagebox.showwarning(t("sin_seleccion"), t("selecciona_para_copiar"))
            return
        cmd = ["ssh"]
        if host.user:
            cmd.append(f"{host.user}@{host.host_name}")
        else:
            cmd.append(host.host_name)
        if host.port:
            cmd.extend(["-p", str(host.port)])
        cmd_str = " ".join(cmd)
        self.view.copy_to_clipboard(cmd_str)
        self.view.show_status("✅ Copiado al portapapeles")

    def test_ssh_connection(self):
        host = self.current_selected()
        if not host or not host.host_name:
            messagebox.showwarning(t("sin_seleccion"), t("selecciona_para_probar"))
            return
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]
        if host.port:
            cmd.extend(["-p", str(host.port)])
        target = f"{host.user}@{host.host_name}" if host.user else host.host_name
        cmd.extend([target, "exit"])
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=7)
            if result.returncode == 0:
                self.view.show_info(t("conexion_ok").format(target=target), "")
            else:
                self.view.show_error(t("fallo_conexion").format(target=target), result.stderr.decode().strip())
        except Exception as e:
            self.view.show_error(t("error_ssh"), f"Error al ejecutar SSH: {e}")

    def export_hosts(self):
        path = filedialog.asksaveasfilename(
            title=t("exportar_json"),
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")]
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump([h.to_dict() for h in self.hosts], f, indent=2)
        self.view.show_info(t("exportar_json"), f"Se exportaron {len(self.hosts)} hosts a {path}.")

    def import_hosts(self):
        path = filedialog.askopenfilename(
            title=t("importar_json"),
            filetypes=[("JSON files", "*.json")]
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                raise ValueError("Formato inválido")
            confirm = messagebox.askyesno(t("importar_json"), t("confirmar_importacion"))
            if not confirm:
                return
            self.hosts = [Host.from_dict(d) for d in data]
            write_config([h.to_dict() for h in self.hosts])
            self.view.update_host_list(self.hosts)
            self.view.show_info(t("importar_json"), f"Importados {len(self.hosts)} hosts.")
        except Exception as e:
            self.view.show_error(t("error"), str(e))

    def current_selected(self) -> Optional[Host]:
        if self.selected_index is None or self.selected_index >= len(self.hosts):
            return None
        return self.hosts[self.selected_index]

    def change_language(self, lang: str) -> None:
        """
        Callback para cambiar idioma en caliente.
        """
        from i18n import load_language
        load_language(lang)
        # Actualizar título de ventana
        self.view.root.title(t("app_title"))
        self.view.show_status(f"Idioma cambiado a {lang}")

    def toggle_readonly(self, readonly: bool) -> None:
        """
        Callback para activar/desactivar modo solo lectura.
        """
        self.view.set_readonly(readonly)
        msg = t("solo_lectura_msg") if readonly else ""
        self.view.show_status(msg)
