import tkinter as tk
from tkinter import messagebox
import subprocess
from auth import get_password_from_pass
from i18n import t

def build_gui(self, extra_fields):
    left_frame = tk.Frame(self.root)
    left_frame.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

    # Buscador
    self.search_var = getattr(self, "search_var", tk.StringVar())
    self.search_var.trace("w", lambda *args: self.refresh_list_with_search())
    search_container = tk.Frame(left_frame)
    search_container.pack(fill=tk.X, pady=(0, 4))
    search_label = tk.Label(search_container, text=t("buscar_host"))
    search_label.pack(side=tk.LEFT, padx=(4, 4))
    search_entry = tk.Entry(search_container, textvariable=self.search_var, width=30)
    search_entry.pack(side=tk.LEFT)
    search_entry.focus_set()

    # Lista de hosts
    self.scrollbar = tk.Scrollbar(left_frame, orient=tk.VERTICAL)
    self.host_listbox = tk.Listbox(left_frame, width=30, yscrollcommand=self.scrollbar.set)
    self.scrollbar.config(command=self.host_listbox.yview)
    self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    self.host_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    self.host_listbox.bind("<<ListboxSelect>>", lambda e: on_select(self))

    self.right_frame = tk.Frame(self.root)
    self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

    self.fields = {}
    all_fields = ["Host", "HostName", "User", "Port"] + extra_fields
    for field in all_fields:
        label = tk.Label(self.right_frame, text=field)
        label.pack()
        entry = tk.Entry(self.right_frame, width=50)
        entry.pack()
        self.fields[field] = entry

    pwd_label = tk.Label(self.right_frame, text="Password")
    pwd_label.pack()
    pwd_frame = tk.Frame(self.right_frame)
    pwd_frame.pack(pady=(0, 5))
    self.password_entry = tk.Entry(pwd_frame, width=45, show='*')
    self.password_entry.pack(side=tk.LEFT)
    self.show_password_button = tk.Button(pwd_frame, text=t("mostrar_contrasena"), command=lambda: toggle_password(self))
    self.show_password_button.pack(side=tk.LEFT, padx=5)

    identity_label = tk.Label(self.right_frame, text="IdentityFile (uno por línea)")
    identity_label.pack()
    self.identityfile_text = tk.Text(self.right_frame, height=4, width=50)
    self.identityfile_text.pack()

    # Botón para seleccionar archivo
    tk.Button(self.right_frame, text=t("clave_ssh"), command=self.select_identity_file).pack(pady=(2, 5))

    self.button_frame = tk.Frame(self.right_frame)
    self.button_frame.pack(pady=10)
    tk.Button(self.button_frame, text=t("nuevo"), command=self.new_host).grid(row=0, column=0, padx=5)
    tk.Button(self.button_frame, text=t("guardar"), command=self.save_host).grid(row=0, column=1, padx=5)
    tk.Button(self.button_frame, text=t("eliminar"), command=self.delete_host).grid(row=0, column=2, padx=5)
    tk.Button(self.button_frame, text=t("restaurar_backup"), command=self.restore_backup).grid(row=0, column=3, padx=5)
    tk.Button(self.button_frame, text=t("copiar_ssh"), command=self.copy_ssh_command).grid(row=0, column=4, padx=5)
    tk.Button(self.button_frame, text=t("test_ssh"), command=self.test_ssh_connection).grid(row=0, column=6, padx=5)
    tk.Button(self.button_frame, text=t("exportar_json"), command=self.export_hosts_to_json).grid(row=1, column=0, padx=5, pady=(5, 0))
    tk.Button(self.button_frame, text=t("importar_json"), command=self.import_hosts_from_json).grid(row=1, column=1, padx=5, pady=(5, 0))
    self.status_label = tk.Label(self.right_frame, text="", fg="green")
    self.status_label.pack(pady=(5, 0))

def on_select(self):
    selection = self.host_listbox.curselection()
    if selection:
        index = selection[0]
        self.selected_index = index
        host = self.hosts[index]
        for key, entry in self.fields.items():
            entry.delete(0, tk.END)
            entry.insert(0, host.get(key, ""))
        self.identityfile_text.delete("1.0", tk.END)
        identity_files = host.get("IdentityFile", [])
        if isinstance(identity_files, str):
            identity_files = [identity_files]
        self.identityfile_text.insert(tk.END, "\n".join(identity_files))
        self.password_entry.delete(0, tk.END)
        if host.get("Host"):
            pass_key = f"sshConfigGUI/host-{host['Host']}/password"
            try:
                password = get_password_from_pass(pass_key)
            except subprocess.CalledProcessError:
                password = ""
            self.password_entry.insert(0, password or "")
        if self.password_shown:
            toggle_password(self)

def toggle_password(self):
    if self.password_shown:
        self.password_entry.config(show='*')
        self.password_shown = False
        self.show_password_button.config(text=t("mostrar_contrasena"))
    else:
        self.password_entry.config(show='')
        self.password_shown = True
        self.show_password_button.config(text=t("ocultar_contrasena"))