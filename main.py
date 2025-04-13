import os
import re
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog

CONFIG_PATH = os.path.expanduser("~/.ssh/config")
BACKUP_PATH = CONFIG_PATH + ".bak"

class SSHConfigManager:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Config Manager")
        self.hosts = []
        self.selected_index = None

        self.extra_fields = ["ProxyJump", "LocalForward", "RemoteForward", "ServerAliveInterval"]

        self.build_gui()
        self.load_config()

    def build_gui(self):
        self.left_frame = tk.Frame(self.root)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        self.scrollbar = tk.Scrollbar(self.left_frame, orient=tk.VERTICAL)
        self.host_listbox = tk.Listbox(self.left_frame, width=30, yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.host_listbox.yview)

        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.host_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.host_listbox.bind("<<ListboxSelect>>", self.on_select)

        self.right_frame = tk.Frame(self.root)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.fields = {}
        all_fields = ["Host", "HostName", "User", "Port"] + self.extra_fields
        for field in all_fields:
            label = tk.Label(self.right_frame, text=field)
            label.pack()
            entry = tk.Entry(self.right_frame, width=50)
            entry.pack()
            self.fields[field] = entry

        # Múltiples IdentityFile
        label = tk.Label(self.right_frame, text="IdentityFile (uno por línea)")
        label.pack()
        self.identityfile_text = tk.Text(self.right_frame, height=4, width=50)
        self.identityfile_text.pack()

        self.button_frame = tk.Frame(self.right_frame)
        self.button_frame.pack(pady=10)

        tk.Button(self.button_frame, text="Nuevo", command=self.new_host).grid(row=0, column=0, padx=5)
        tk.Button(self.button_frame, text="Guardar", command=self.save_host).grid(row=0, column=1, padx=5)
        tk.Button(self.button_frame, text="Eliminar", command=self.delete_host).grid(row=0, column=2, padx=5)
        tk.Button(self.button_frame, text="Restaurar backup", command=self.restore_backup).grid(row=0, column=3, padx=5)

        self.status_label = tk.Label(self.right_frame, text="", fg="green")
        self.status_label.pack(pady=(5, 0))

    def load_config(self):
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
        self.hosts.sort(key=lambda h: h.get("Host", "").lower())
        self.host_listbox.delete(0, tk.END)
        for host in self.hosts:
            self.host_listbox.insert(tk.END, host.get("Host", ""))

    def on_select(self, event):
        selection = self.host_listbox.curselection()
        if selection:
            index = selection[0]
            self.selected_index = index
            host = self.hosts[index]
            for key in self.fields:
                self.fields[key].delete(0, tk.END)
                self.fields[key].insert(0, host.get(key, ""))

            self.identityfile_text.delete("1.0", tk.END)
            identity_files = host.get("IdentityFile", [])
            if isinstance(identity_files, str):
                identity_files = [identity_files]
            self.identityfile_text.insert(tk.END, "\n".join(identity_files))

    def new_host(self):
        for entry in self.fields.values():
            entry.delete(0, tk.END)
        self.identityfile_text.delete("1.0", tk.END)
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

        data = {key: entry.get().strip() for key, entry in self.fields.items() if entry.get().strip()}

        identity_files = self.identityfile_text.get("1.0", tk.END).strip().splitlines()
        if identity_files:
            data["IdentityFile"] = identity_files

        if not data.get("Host"):
            messagebox.showerror("Error", "El campo 'Host' es obligatorio.")
            return

        if self.selected_index is not None:
            self.hosts[self.selected_index] = data
        else:
            self.hosts.append(data)
        self.write_config()
        self.refresh_listbox()
        self.status_label.config(text="✅ Cambios guardados")

    def is_valid_hostname_or_ip(self, value):
        hostname_regex = re.compile(r'^[a-zA-Z0-9.-]+$')
        ip_regex = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        return hostname_regex.match(value) or ip_regex.match(value)

    def delete_host(self):
        if self.selected_index is not None:
            confirm = messagebox.askyesno("Confirmar eliminación", "¿Estás seguro de que quieres eliminar este host?")
            if confirm:
                del self.hosts[self.selected_index]
                self.selected_index = None
                self.write_config()
                self.refresh_listbox()
                for entry in self.fields.values():
                    entry.delete(0, tk.END)
                self.identityfile_text.delete("1.0", tk.END)
                self.status_label.config(text="✅ Host eliminado")

    def write_config(self):
        os.rename(CONFIG_PATH, BACKUP_PATH)

        with open(CONFIG_PATH, 'w') as f:
            for host in self.hosts:
                f.write(f"Host {host.get('Host')}\n")
                for key in ["HostName", "User", "Port"] + self.extra_fields:
                    if key in host:
                        f.write(f"    {key} {host[key]}\n")
                if "IdentityFile" in host:
                    for identity in host["IdentityFile"]:
                        f.write(f"    IdentityFile {identity}\n")
                f.write("\n")

    def restore_backup(self):
        if os.path.exists(BACKUP_PATH):
            confirm = messagebox.askyesno("Restaurar backup", "¿Deseas restaurar la última copia de seguridad?")
            if confirm:
                os.rename(BACKUP_PATH, CONFIG_PATH)
                self.load_config()
                messagebox.showinfo("Restaurado", "Backup restaurado correctamente.")
                self.status_label.config(text="✅ Backup restaurado")
        else:
            messagebox.showerror("Error", "No se encontró un archivo de backup para restaurar.")
            self.status_label.config(text="")

if __name__ == "__main__":
    root = tk.Tk()
    app = SSHConfigManager(root)
    root.mainloop()
