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
        # Identificador para temporizador de auto-bloqueo
        self.lock_id = None

        # Preparar entorno de contraseña maestra e iniciar autenticación
        self.ensure_pass_ready()
        self.authenticate()

    def ensure_pass_ready(self):
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
        pw_actual = self.get_password_from_pass()
        if pw_actual is None:
            # Crear contraseña maestra nueva si no existe
            nueva = simpledialog.askstring("Crear contraseña", "Establece una contraseña para la aplicación:", show='*')
            if nueva:
                subprocess.run(["pass", "insert", "-m", PASS_ENTRY], input=nueva.encode())
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

        self.build_gui()
        self.load_config()

    def get_password_from_pass(self):
        try:
            result = subprocess.run(["pass", "show", PASS_ENTRY], capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None

    def build_gui(self):
        # Marco izquierdo: lista de hosts
        self.left_frame = tk.Frame(self.root)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        self.scrollbar = tk.Scrollbar(self.left_frame, orient=tk.VERTICAL)
        self.host_listbox = tk.Listbox(self.left_frame, width=30, yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.host_listbox.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.host_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.host_listbox.bind("<<ListboxSelect>>", self.on_select)

        # Marco derecho: campos de detalles del host
        self.right_frame = tk.Frame(self.root)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.fields = {}
        # Campos básicos y avanzados (excepto Password, que se maneja aparte)
        all_fields = ["Host", "HostName", "User", "Port"] + self.extra_fields
        for field in all_fields:
            label = tk.Label(self.right_frame, text=field)
            label.pack()
            entry = tk.Entry(self.right_frame, width=50)
            entry.pack()
            self.fields[field] = entry

        # Campo de contraseña (Password) con visibilidad alternable
        pwd_label = tk.Label(self.right_frame, text="Password")
        pwd_label.pack()
        pwd_frame = tk.Frame(self.right_frame)
        pwd_frame.pack(pady=(0, 5))
        self.password_entry = tk.Entry(pwd_frame, width=45, show='*')
        self.password_entry.pack(side=tk.LEFT)
        self.show_password_button = tk.Button(pwd_frame, text="Mostrar", command=self.toggle_password)
        self.show_password_button.pack(side=tk.LEFT, padx=5)

        # Campo de múltiples IdentityFile
        identity_label = tk.Label(self.right_frame, text="IdentityFile (uno por línea)")
        identity_label.pack()
        self.identityfile_text = tk.Text(self.right_frame, height=4, width=50)
        self.identityfile_text.pack()

        # Botones de acción
        self.button_frame = tk.Frame(self.right_frame)
        self.button_frame.pack(pady=10)
        tk.Button(self.button_frame, text="Nuevo", command=self.new_host).grid(row=0, column=0, padx=5)
        tk.Button(self.button_frame, text="Guardar", command=self.save_host).grid(row=0, column=1, padx=5)
        tk.Button(self.button_frame, text="Eliminar", command=self.delete_host).grid(row=0, column=2, padx=5)
        tk.Button(self.button_frame, text="Restaurar backup", command=self.restore_backup).grid(row=0, column=3, padx=5)

        # Etiqueta de estado
        self.status_label = tk.Label(self.right_frame, text="", fg="green")
        self.status_label.pack(pady=(5, 0))

        # Enlazar eventos para controlar inactividad y programar auto-bloqueo
        self.root.bind_all("<Key>", self.reset_timer)
        self.root.bind_all("<Button-1>", self.reset_timer)
        self.root.bind_all("<MouseWheel>", self.reset_timer)
        self.root.bind_all("<Button-4>", self.reset_timer)  # Scroll up en Linux
        self.root.bind_all("<Button-5>", self.reset_timer)  # Scroll down en Linux
        self.reset_timer()  # Iniciar temporizador de inactividad

    def reset_timer(self, event=None):
        # Reiniciar temporizador de auto-bloqueo (5 minutos)
        if self.lock_id:
            try:
                self.root.after_cancel(self.lock_id)
            except Exception:
                pass
        self.lock_id = self.root.after(300000, self.lock_application)

    def lock_application(self):
        # Bloquear la aplicación por inactividad y requerir autenticación para continuar
        self.root.withdraw()  # Ocultar ventana principal
        pw = simpledialog.askstring("Bloqueado por inactividad",
                                    "La sesión se ha bloqueado por inactividad.\nIntroduce la contraseña para desbloquear:", show='*')
        pw_actual = self.get_password_from_pass()
        if pw is None or pw_actual is None or pw != pw_actual:
            messagebox.showerror("Acceso denegado", "Contraseña incorrecta.")
            self.root.destroy()
        else:
            # Restaurar ventana principal y reiniciar temporizador de inactividad
            self.root.deiconify()
            self.reset_timer()

    def on_select(self, event):
        selection = self.host_listbox.curselection()
        if selection:
            index = selection[0]
            self.selected_index = index
            host = self.hosts[index]
            # Rellenar campos básicos
            for key, entry in self.fields.items():
                entry.delete(0, tk.END)
                entry.insert(0, host.get(key, ""))
            # Rellenar campos de IdentityFile
            self.identityfile_text.delete("1.0", tk.END)
            identity_files = host.get("IdentityFile", [])
            if isinstance(identity_files, str):
                identity_files = [identity_files]
            self.identityfile_text.insert(tk.END, "\n".join(identity_files))
            # Rellenar el campo de contraseña desde 'pass'
            self.password_entry.delete(0, tk.END)
            if host.get("Host"):
                pass_key = f"sshConfigGUI/host-{host['Host']}/password"
                try:
                    result = subprocess.run(["pass", "show", pass_key], capture_output=True, text=True, check=True)
                    password = result.stdout.strip()
                except subprocess.CalledProcessError:
                    password = ""
                self.password_entry.insert(0, password)
            # Restablecer visibilidad de contraseña a oculta por defecto al cambiar de host
            if self.password_shown:
                self.toggle_password()

    def new_host(self):
        # Limpiar todos los campos para un nuevo host
        for entry in self.fields.values():
            entry.delete(0, tk.END)
        self.identityfile_text.delete("1.0", tk.END)
        self.password_entry.delete(0, tk.END)
        # Restablecer visibilidad de contraseña (oculto por defecto)
        if self.password_shown:
            self.toggle_password()
        self.selected_index = None
        self.status_label.config(text="")

    def save_host(self):
        host_name = self.fields["HostName"].get().strip()
        port = self.fields["Port"].get().strip()

        if host_name and not self.is_valid_hostname_or_ip(host_name):
            messagebox.showerror("Error", f"HostName no válido: {host_name}")
            return

        if port and not port.isdigit():
            messagebox.showerror("Error", f"El puerto debe ser un número entero: {port}")
            return

        # Recolectar datos de campos de texto (excluyendo contraseña)
        data = {key: entry.get().strip() for key, entry in self.fields.items() if entry.get().strip()}
        # Recolectar IdentityFile(s) del campo de texto multilinea
        identity_files = self.identityfile_text.get("1.0", tk.END).strip().splitlines()
        if identity_files:
            data["IdentityFile"] = identity_files

        if not data.get("Host"):
            messagebox.showerror("Error", "El campo 'Host' es obligatorio.")
            return

        # Actualizar o agregar host en la lista
        if self.selected_index is not None:
            self.hosts[self.selected_index] = data
        else:
            self.hosts.append(data)

        # Guardar contraseña en 'pass' si está presente
        pwd_value = self.password_entry.get().strip()
        pass_key = f"sshConfigGUI/host-{data['Host']}/password"
        if pwd_value:
            subprocess.run(["pass", "insert", "-m", "--force", pass_key], input=pwd_value.encode())
        else:
            subprocess.run(["pass", "rm", "-f", pass_key])

        # Escribir configuración a archivo y actualizar interfaz
        self.write_config()
        self.refresh_listbox()
        self.status_label.config(text="✅ Cambios guardados")

    def is_valid_hostname_or_ip(self, value):
        hostname_regex = re.compile(r'^[a-zA-Z0-9.-]+$')
        ip_regex = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        return bool(hostname_regex.match(value) or ip_regex.match(value))

    def delete_host(self):
        if self.selected_index is not None:
            confirm = messagebox.askyesno("Confirmar eliminación", "¿Estás seguro de que quieres eliminar este host?")
            if confirm:
                # Obtener nombre del host antes de eliminar
                host_alias = self.hosts[self.selected_index].get("Host")
                # Eliminar host de la lista
                del self.hosts[self.selected_index]
                self.selected_index = None
                # Guardar cambios en archivo
                self.write_config()
                self.refresh_listbox()
                # Limpiar campos de entrada
                for entry in self.fields.values():
                    entry.delete(0, tk.END)
                self.identityfile_text.delete("1.0", tk.END)
                self.password_entry.delete(0, tk.END)
                # Eliminar contraseña asociada del almacén 'pass'
                if host_alias:
                    pass_key = f"sshConfigGUI/host-{host_alias}/password"
                    subprocess.run(["pass", "rm", "-f", pass_key])
                self.status_label.config(text="✅ Host eliminado")

    def write_config(self):
        # Hacer copia de seguridad antes de escribir la nueva configuración
        if os.path.exists(CONFIG_PATH):
            os.rename(CONFIG_PATH, BACKUP_PATH)
        else:
            open(CONFIG_PATH, 'a').close()  # crear archivo vacío si no existía

        with open(CONFIG_PATH, 'w') as f:
            for host in self.hosts:
                f.write(f"Host {host.get('Host')}\n")
                for key in ["HostName", "User", "Port"] + self.extra_fields:
                    if key in host:
                        f.write(f"    {key} {host[key]}\n")
                if "IdentityFile" in host:
                    identities = host["IdentityFile"]
                    if isinstance(identities, str):
                        identities = [identities]
                    for identity in identities:
                        f.write(f"    IdentityFile {identity}\n")
                f.write("\n")

    def restore_backup(self):
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

    def load_config(self):
        # Asegurarse de que el archivo de configuración existe
        if not os.path.exists(CONFIG_PATH):
            open(CONFIG_PATH, 'a').close()

        with open(CONFIG_PATH, 'r') as f:
            lines = f.readlines()

        self.hosts = []
        current = {}
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("Host "):
                if current:
                    self.hosts.append(current)
                current = {"Host": stripped.split()[1]}
            elif stripped:
                if current:
                    key, *rest = stripped.split()
                    value = ' '.join(rest)
                    if key == "IdentityFile":
                        current.setdefault("IdentityFile", []).append(value)
                    else:
                        current[key] = value
        if current:
            self.hosts.append(current)

        self.refresh_listbox()

    def refresh_listbox(self):
        # Ordenar hosts alfabéticamente (ignorando mayúsculas)
        self.hosts.sort(key=lambda h: h.get("Host", "").lower())
        self.host_listbox.delete(0, tk.END)
        for host in self.hosts:
            self.host_listbox.insert(tk.END, host.get("Host", ""))

    def toggle_password(self):
        # Alternar visibilidad de la contraseña en el campo Password
        if self.password_shown:
            # Ocultar contraseña
            self.password_entry.config(show='*')
            self.password_shown = False
            self.show_password_button.config(text="Mostrar")
        else:
            # Mostrar contraseña en texto plano
            self.password_entry.config(show='')
            self.password_shown = True
            self.show_password_button.config(text="Ocultar")

if __name__ == "__main__":
    import shutil
    root = tk.Tk()
    app = SSHConfigManager(root)
    root.mainloop()
