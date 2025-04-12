import os
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog

CONFIG_PATH = os.path.expanduser("~/.ssh/config")


class SSHConfigManager:
    def __init__(self, root):
        self.root = root
        self.root.title("SSH Config Manager")
        self.hosts = []
        self.selected_index = None

        self.build_gui()
        self.load_config()

    def build_gui(self):
        self.left_frame = tk.Frame(self.root)
        self.left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        self.host_listbox = tk.Listbox(self.left_frame, width=30)
        self.host_listbox.pack(fill=tk.BOTH, expand=True)
        self.host_listbox.bind("<<ListboxSelect>>", self.on_select)

        self.right_frame = tk.Frame(self.root)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.fields = {}
        for field in ["Host", "HostName", "User", "Port", "IdentityFile"]:
            label = tk.Label(self.right_frame, text=field)
            label.pack()
            entry = tk.Entry(self.right_frame, width=50)
            entry.pack()
            self.fields[field] = entry

        self.button_frame = tk.Frame(self.right_frame)
        self.button_frame.pack(pady=10)

        tk.Button(self.button_frame, text="Nuevo", command=self.new_host).grid(row=0, column=0, padx=5)
        tk.Button(self.button_frame, text="Guardar", command=self.save_host).grid(row=0, column=1, padx=5)
        tk.Button(self.button_frame, text="Eliminar", command=self.delete_host).grid(row=0, column=2, padx=5)

    def load_config(self):
        if not os.path.exists(CONFIG_PATH):
            open(CONFIG_PATH, 'a').close()

        with open(CONFIG_PATH, 'r') as f:
            lines = f.readlines()

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
                    current[key] = ' '.join(rest)
        if current:
            self.hosts.append(current)

        self.refresh_listbox()

    def refresh_listbox(self):
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

    def new_host(self):
        for entry in self.fields.values():
            entry.delete(0, tk.END)
        self.selected_index = None

    def save_host(self):
        data = {key: entry.get().strip() for key, entry in self.fields.items() if entry.get().strip()}
        if not data.get("Host"):
            messagebox.showerror("Error", "El campo 'Host' es obligatorio.")
            return

        if self.selected_index is not None:
            self.hosts[self.selected_index] = data
        else:
            self.hosts.append(data)
        self.write_config()
        self.refresh_listbox()

    def delete_host(self):
        if self.selected_index is not None:
            del self.hosts[self.selected_index]
            self.selected_index = None
            self.write_config()
            self.refresh_listbox()
            for entry in self.fields.values():
                entry.delete(0, tk.END)

    def write_config(self):
        backup_path = CONFIG_PATH + ".bak"
        os.rename(CONFIG_PATH, backup_path)

        with open(CONFIG_PATH, 'w') as f:
            for host in self.hosts:
                f.write(f"Host {host.get('Host')}\n")
                for key in ["HostName", "User", "Port", "IdentityFile"]:
                    if key in host:
                        f.write(f"    {key} {host[key]}\n")
                f.write("\n")

        messagebox.showinfo("Éxito", f"Archivo guardado. Backup en {backup_path}")


if __name__ == "__main__":
    root = tk.Tk()
    app = SSHConfigManager(root)
    root.mainloop()
