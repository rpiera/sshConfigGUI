import os
import re
import subprocess
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog

CONFIG_PATH = os.path.expanduser("~/.ssh/config")
BACKUP_PATH = CONFIG_PATH + ".bak"
PASS_ENTRY = "sshConfigGUI/master-password"

class SSHConfigManager:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Config Manager")
        self.hosts = []
        self.selected_index = None

        # Campos avanzados soportados
        self.extra_fields = ["ProxyJump", "LocalForward", "RemoteForward", "ServerAliveInterval"]
        # Estados de visibilidad de campos sensibles
        self.identity_shown = False
        self.password_shown = False
        # Buffer temporal para IdentityFile no guardado
        self.unsaved_identity = None

        # Preparar entorno de contraseña maestra e iniciar autenticación
        self.ensure_pass_ready()
        self.authenticate()

    def ensure_pass_ready(self):
        """Verifica que 'gpg' y 'pass' estén instalados y que exista una clave GPG para inicializar pass."""
        # Instalar gpg y pass si no están disponibles
        if not shutil.which("gpg") or not shutil.which("pass"):
            messagebox.showinfo("Instalación necesaria", "Se instalarán 'gpg' y 'pass'. Requiere contraseña de administrador.")
            subprocess.run(["sudo", "apt", "update"])
            subprocess.run(["sudo", "apt", "install", "-y", "gnupg2", "pass"])

        # Verificar si hay al menos una clave GPG
        result = subprocess.run(["gpg", "--list-keys"], capture_output=True, text=True)
        if "pub" not in result.stdout:
            # Crear una nueva clave GPG automáticamente (sin contraseña)
            key_script = '''
            %echo Generating key
            Key-Type: RSA
            Key-Length: 2048
            Subkey-Type: RSA
            Subkey-Length: 2048
            Name-Real: sshConfigGUI
            Name-Email: sshconfiggui@example.com
            Expire-Date: 0
            %no-protection
            %commit
            '''.strip()
            with open("gpg_batch.txt", "w") as f:
                f.write(key_script)
            subprocess.run(["gpg", "--batch", "--generate-key", "gpg_batch.txt"])
            os.remove("gpg_batch.txt")

        # Inicializar el almacén de 'pass' con la clave GPG disponible
        result = subprocess.run(["gpg", "--list-keys", "--with-colons"], capture_output=True, text=True)
        key_id = next((line.split(':')[4] for line in result.stdout.splitlines() if line.startswith("pub")), None)
        if key_id:
            subprocess.run(["pass", "init", key_id])

    def authenticate(self):
        """Solicita o establece la contraseña maestra utilizando 'pass'. Si es correcta, construye la GUI."""
        pw_actual = self.get_password_from_pass()
        if pw_actual is None:
            # Solicitar nueva contraseña maestra si no existe almacenada
            nueva = simpledialog.askstring("Crear contraseña", "Establece una contraseña para la aplicación:", show='*')
            if nueva:
                subprocess.run(["pass", "insert", "-m", PASS_ENTRY], input=nueva.encode())
                # Mostrar confirmación
                self.status_label = tk.Label(self.root, text="✅ Contraseña guardada en pass", fg="green")
                self.status_label.pack()
            else:
                messagebox.showerror("Cancelado", "No se ha establecido contraseña.")
                self.root.destroy()
                return
        else:
            # Pedir contraseña maestra al usuario
            pw = simpledialog.askstring("Acceso protegido", "Introduce la contraseña:", show='*')
            if pw != pw_actual:
                messagebox.showerror("Acceso denegado", "Contraseña incorrecta.")
                self.root.destroy()
                return

        # Construir la interfaz gráfica y cargar configuración tras autenticación exitosa
        self.build_gui()
        self.load_config()

    def get_password_from_pass(self):
        """Recupera la contraseña maestra almacenada con 'pass', o None si no existe."""
        try:
            result = subprocess.run(["pass", "show", PASS_ENTRY], capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None

    def build_gui(self):
        """Construye los elementos de la interfaz (listado de hosts y formulario de detalles)."""
        # Panel izquierdo: lista de hosts con scrollbar
        self.left_frame = tk.Frame(self.root)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        self.scrollbar = tk.Scrollbar(self.left_frame, orient=tk.VERTICAL)
        self.host_listbox = tk.Listbox(self.left_frame, width=30, yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.host_listbox.yview)

        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.host_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.host_listbox.bind("<<ListboxSelect>>", self.on_select)

        # Panel derecho: formulario de campos
        self.right_frame = tk.Frame(self.root)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Campos estándar + avanzados
        self.fields = {}
        all_fields = ["Host", "HostName", "User", "Port"] + self.extra_fields
        for field in all_fields:
            label = tk.Label(self.right_frame, text=field)
            label.pack()
            entry = tk.Entry(self.right_frame, width=50)
            entry.pack()
            self.fields[field] = entry

        # Campo IdentityFile (multilínea) con toggle de visibilidad
        id_label_frame = tk.Frame(self.right_frame)
        id_label_frame.pack(fill=tk.X)
        id_label = tk.Label(id_label_frame, text="IdentityFile (uno por línea)")
        id_label.pack(side=tk.LEFT)
        self.id_toggle_btn = tk.Button(id_label_frame, text="Mostrar", command=self.toggle_identity)
        self.id_toggle_btn.pack(side=tk.RIGHT)

        self.identityfile_text = tk.Text(self.right_frame, height=4, width=50)
        self.identityfile_text.pack()
        # Por defecto, iniciar oculto (deshabilitado hasta selección)
        self.identityfile_text.config(state=tk.DISABLED)

        # Campo Password con toggle de visibilidad
        pass_label_frame = tk.Frame(self.right_frame)
        pass_label_frame.pack(fill=tk.X)
        pass_label = tk.Label(pass_label_frame, text="Password")
        pass_label.pack(side=tk.LEFT)
        self.pw_toggle_btn = tk.Button(pass_label_frame, text="Mostrar", command=self.toggle_password)
        self.pw_toggle_btn.pack(side=tk.RIGHT)

        self.password_entry = tk.Entry(self.right_frame, width=50, show='*')
        self.password_entry.pack()
        self.fields["Password"] = self.password_entry

        # Botones de acción
        self.button_frame = tk.Frame(self.right_frame)
        self.button_frame.pack(pady=10)

        tk.Button(self.button_frame, text="Nuevo", command=self.new_host).grid(row=0, column=0, padx=5)
        tk.Button(self.button_frame, text="Guardar", command=self.save_host).grid(row=0, column=1, padx=5)
        tk.Button(self.button_frame, text="Eliminar", command=self.delete_host).grid(row=0, column=2, padx=5)
        tk.Button(self.button_frame, text="Restaurar backup", command=self.restore_backup).grid(row=0, column=3, padx=5)

        self.status_label = tk.Label(self.right_frame, text="", fg="green")
        self.status_label.pack(pady=(5, 0))

    def load_config(self):
        """Carga el archivo SSH config en la estructura self.hosts."""
        # Asegurarse de que el archivo exista
        if not os.path.exists(CONFIG_PATH):
            open(CONFIG_PATH, 'a').close()

        with open(CONFIG_PATH, 'r') as f:
            lines = f.readlines()

        self.hosts = []
        current = {}
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("Host "):
                # Nueva sección Host; guardar la anterior si existe
                if current:
                    self.hosts.append(current)
                current = {"Host": stripped.split()[1]}
            elif stripped:
                if current:
                    # Contraseña almacenada como comentario
                    if stripped.startswith("# Password "):
                        current["Password"] = stripped[len("# Password "):]
                        continue
                    # Clave-valor normal
                    key, *rest = stripped.split()
                    value = ' '.join(rest)
                    if key == "IdentityFile":
                        current.setdefault("IdentityFile", []).append(value)
                    elif key == "Password":
                        # En caso de línea Password no comentada (no estándar)
                        current["Password"] = value
                    else:
                        current[key] = value
        # Añadir el último host procesado
        if current:
            self.hosts.append(current)

        # Ordenar la lista de hosts por nombre
        self.refresh_listbox()

    def refresh_listbox(self):
        """Actualiza la lista visual de hosts, ordenándolos alfabéticamente."""
        self.hosts.sort(key=lambda h: h.get("Host", "").lower())
        self.host_listbox.delete(0, tk.END)
        for host in self.hosts:
            self.host_listbox.insert(tk.END, host.get("Host", ""))

    def on_select(self, event):
        """Maneja la selección de un host de la lista, mostrando sus datos en el formulario."""
        selection = self.host_listbox.curselection()
        if selection:
            index = selection[0]
            self.selected_index = index
            host = self.hosts[index]
            # Cargar cada campo de texto simple
            for key in self.fields:
                self.fields[key].delete(0, tk.END)
                self.fields[key].insert(0, host.get(key, ""))

            # Cargar IdentityFile con visibilidad según estado
            self.identityfile_text.config(state=tk.NORMAL)
            self.identityfile_text.delete("1.0", tk.END)
            identity_files = host.get("IdentityFile", [])
            if isinstance(identity_files, str):
                identity_files = [identity_files]
            if not identity_files:
                identity_files = []
            if not self.identity_shown:
                # Mostrar asteriscos en lugar de rutas reales
                for identity in identity_files:
                    self.identityfile_text.insert(tk.END, "*" * len(identity) + "\n")
                self.identityfile_text.config(state=tk.DISABLED)
            else:
                for identity in identity_files:
                    self.identityfile_text.insert(tk.END, identity + "\n")
                self.identityfile_text.config(state=tk.NORMAL)

            # Limpiar buffer temporal de identidades (cambio de host invalida ediciones no guardadas anteriores)
            self.unsaved_identity = None

    def new_host(self):
        """Prepara el formulario para introducir un nuevo host (campos vacíos)."""
        for entry in self.fields.values():
            entry.delete(0, tk.END)
        self.identityfile_text.config(state=tk.NORMAL)
        self.identityfile_text.delete("1.0", tk.END)
        # Si estaba oculto, mantenerlo oculto deshabilitando de nuevo
        if not self.identity_shown:
            self.identityfile_text.config(state=tk.DISABLED)
        self.selected_index = None
        self.status_label.config(text="")
        self.unsaved_identity = None

    def save_host(self):
        """Guarda los datos del formulario en self.hosts (añadiendo o actualizando) y escribe el archivo config."""
        # Validaciones de campos HostName y Port
        host_name = self.fields["HostName"].get().strip()
        port = self.fields["Port"].get().strip()

        if host_name and not self.is_valid_hostname_or_ip(host_name):
            messagebox.showerror("Error", f"HostName no válido: {host_name}")
            return
        if port and not port.isdigit():
            messagebox.showerror("Error", f"El puerto debe ser un número entero: {port}")
            return

        # Construir diccionario de datos desde los campos
        data = {key: entry.get().strip() for key, entry in self.fields.items() if entry.get().strip()}

        # Manejar IdentityFile según estado de visibilidad
        if self.identity_shown:
            # Tomar texto actual (visible) directamente
            identity_lines = self.identityfile_text.get("1.0", tk.END).strip().splitlines()
            identity_files = [line for line in identity_lines if line]
        else:
            if self.selected_index is not None:
                if self.unsaved_identity is not None:
                    identity_files = [line for line in self.unsaved_identity if line]
                else:
                    identity_files = self.hosts[self.selected_index].get("IdentityFile", [])
                    if isinstance(identity_files, str):
                        identity_files = [identity_files] if identity_files else []
            else:
                identity_files = [line for line in self.unsaved_identity if line] if self.unsaved_identity else []

        if identity_files:
            data["IdentityFile"] = identity_files

        # Campo Host es obligatorio
        if not data.get("Host"):
            messagebox.showerror("Error", "El campo 'Host' es obligatorio.")
            return

        # Actualizar lista interna de hosts
        if self.selected_index is not None:
            self.hosts[self.selected_index] = data
        else:
            self.hosts.append(data)

        # Escribir al archivo y actualizar lista visual
        self.write_config()
        self.refresh_listbox()
        self.status_label.config(text="✅ Cambios guardados")
        self.unsaved_identity = None

    def is_valid_hostname_or_ip(self, value):
        """Verifica si una cadena es un nombre de host o dirección IP válidos."""
        hostname_regex = re.compile(r'^[a-zA-Z0-9.-]+$')
        ip_regex = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        return bool(hostname_regex.match(value) or ip_regex.match(value))

    def delete_host(self):
        """Elimina el host seleccionado tras pedir confirmación al usuario."""
        if self.selected_index is not None:
            confirm = messagebox.askyesno("Confirmar eliminación", "¿Estás seguro de que quieres eliminar este host?")
            if confirm:
                del self.hosts[self.selected_index]
                self.selected_index = None
                self.write_config()
                self.refresh_listbox()
                # Limpiar formulario tras eliminar
                for entry in self.fields.values():
                    entry.delete(0, tk.END)
                self.identityfile_text.config(state=tk.NORMAL)
                self.identityfile_text.delete("1.0", tk.END)
                if not self.identity_shown:
                    self.identityfile_text.config(state=tk.DISABLED)
                self.status_label.config(text="✅ Host eliminado")

    def write_config(self):
        """Escribe la lista de hosts actual (self.hosts) al archivo ~/.ssh/config, creando backup previo."""
        if os.path.exists(CONFIG_PATH):
            try:
                os.replace(CONFIG_PATH, BACKUP_PATH)
            except OSError:
                # Si os.replace falla (distinto filesystem, etc.), intentar copia manual
                import shutil
                shutil.copy2(CONFIG_PATH, BACKUP_PATH)
        # Escribir nuevo archivo de configuración
        with open(CONFIG_PATH, 'w') as f:
            for host in self.hosts:
                f.write(f"Host {host.get('Host')}\n")
                # Escribir campos estándar y avanzados conocidos
                for key in ["HostName", "User", "Port"] + self.extra_fields:
                    if key in host:
                        f.write(f"    {key} {host[key]}\n")
                # Escribir múltiples IdentityFile si existen
                if "IdentityFile" in host:
                    identities = host["IdentityFile"]
                    if isinstance(identities, str):
                        identities = [identities]
                    for identity in identities:
                        f.write(f"    IdentityFile {identity}\n")
                # Escribir Password como comentario si existe
                if "Password" in host:
                    f.write(f"    # Password {host['Password']}\n")
                f.write("\n")

    def restore_backup(self):
        """Restaura la última copia de seguridad del config, con confirmación."""
        if os.path.exists(BACKUP_PATH):
            confirm = messagebox.askyesno("Restaurar backup", "¿Deseas restaurar la última copia de seguridad?")
            if confirm:
                os.replace(BACKUP_PATH, CONFIG_PATH)
                self.load_config()
                messagebox.showinfo("Restaurado", "Backup restaurado correctamente.")
                self.status_label.config(text="✅ Backup restaurado")
        else:
            messagebox.showerror("Error", "No se encontró un archivo de backup para restaurar.")
            self.status_label.config(text="")

    def toggle_identity(self):
        """Alterna la visibilidad del campo IdentityFile entre oculto (***** ocultando rutas) y visible."""
        if self.identity_shown:
            # Pasar a oculto
            self.identity_shown = False
            self.id_toggle_btn.config(text="Mostrar")
            # Guardar contenido actual (posibles cambios no guardados) en buffer temporal
            self.identityfile_text.config(state=tk.NORMAL)
            content = self.identityfile_text.get("1.0", tk.END).strip().splitlines()
            self.unsaved_identity = content
            # Reemplazar texto con asteriscos
            self.identityfile_text.delete("1.0", tk.END)
            for line in content:
                self.identityfile_text.insert(tk.END, "*" * len(line) + "\n")
            self.identityfile_text.config(state=tk.DISABLED)
        else:
            # Pasar a visible
            self.identity_shown = True
            self.id_toggle_btn.config(text="Ocultar")
            self.identityfile_text.config(state=tk.NORMAL)
            # Determinar qué contenido mostrar
            lines_to_show = []
            if self.selected_index is not None:
                if self.unsaved_identity is not None:
                    lines_to_show = [line for line in self.unsaved_identity]
                else:
                    identity_files = self.hosts[self.selected_index].get("IdentityFile", [])
                    if isinstance(identity_files, str):
                        lines_to_show = [identity_files]
                    elif identity_files:
                        lines_to_show = identity_files
            else:
                # Nuevo host (no hay datos guardados aún)
                if self.unsaved_identity is not None:
                    lines_to_show = [line for line in self.unsaved_identity]
                else:
                    lines_to_show = []
            # Mostrar contenido real en el Text
            self.identityfile_text.delete("1.0", tk.END)
            for line in lines_to_show:
                self.identityfile_text.insert(tk.END, line + "\n")
            self.identityfile_text.config(state=tk.NORMAL)

    def toggle_password(self):
        """Alterna la visibilidad del campo Password entre oculto (****) y texto plano."""
        if self.password_shown:
            # Ocultar contraseña
            self.password_shown = False
            self.pw_toggle_btn.config(text="Mostrar")
            self.password_entry.config(show='*')
        else:
            # Mostrar contraseña
            self.password_shown = True
            self.pw_toggle_btn.config(text="Ocultar")
            self.password_entry.config(show='')

# Inicializar y ejecutar la aplicación
if __name__ == "__main__":
    import shutil  # Importar aquí para usar shutil.which en ensure_pass_ready
    root = tk.Tk()
    app = SSHConfigManager(root)
    root.mainloop()
