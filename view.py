import tkinter as tk
from tkinter import messagebox, filedialog
from typing import List, Callable, Optional

from models import Host
from i18n import t

# Campos extra para la interfaz
EXTRA_FIELDS = ["ProxyJump", "LocalForward", "RemoteForward", "ServerAliveInterval"]

class SSHConfigView:
    """
    Vista de la aplicación: construye y gestiona la UI en Tkinter.
    Incluye selector de idioma y modo solo lectura.
    """
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.geometry("900x500")
        self.root.title(t("app_title"))

        # Callbacks registrados por el controlador
        self._new_cb: Optional[Callable[[], None]] = None
        self._save_cb: Optional[Callable[[], None]] = None
        self._delete_cb: Optional[Callable[[], None]] = None
        self._restore_cb: Optional[Callable[[], None]] = None
        self._search_cb: Optional[Callable[[str], None]] = None
        self._select_cb: Optional[Callable[[Optional[int]], None]] = None
        self._copy_cb: Optional[Callable[[], None]] = None
        self._test_cb: Optional[Callable[[], None]] = None
        self._export_cb: Optional[Callable[[], None]] = None
        self._import_cb: Optional[Callable[[], None]] = None
        self._lang_cb: Optional[Callable[[str], None]] = None
        self._toggle_readonly_cb: Optional[Callable[[bool], None]] = None

        # Barra superior: idioma y modo solo lectura
        top_frame = tk.Frame(self.root)
        top_frame.pack(fill=tk.X, pady=(5, 5))
        tk.Label(top_frame, text=t("idioma")).pack(side=tk.LEFT, padx=(10, 4))
        self.lang_var = tk.StringVar(value="es")
        tk.OptionMenu(top_frame, self.lang_var, "es", "en", command=self._on_lang_change).pack(side=tk.LEFT)
        self.readonly_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            top_frame,
            text=t("modo_solo_lectura"),
            variable=self.readonly_var,
            command=self._on_toggle_readonly
        ).pack(side=tk.LEFT, padx=(20, 0))

        self._build_sidebar()
        self._build_detail_panel()
        self._build_status_bar()

    def _on_lang_change(self, selected: str):
        if self._lang_cb:
            self._lang_cb(selected)

    def _on_toggle_readonly(self):
        if self._toggle_readonly_cb:
            self._toggle_readonly_cb(self.readonly_var.get())

    def _build_sidebar(self):
        sidebar = tk.Frame(self.root)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=10, pady=10)

        tk.Label(sidebar, text=t("buscar_host")).pack(anchor="w")
        self.search_var = tk.StringVar()
        tk.Entry(sidebar, textvariable=self.search_var, width=30).pack(fill=tk.X, pady=(0, 5))
        self.search_var.trace_add("write", lambda *_: self._search_cb and self._search_cb(self.search_var.get()))

        self.host_listbox = tk.Listbox(sidebar, width=30)
        scrollbar = tk.Scrollbar(sidebar, command=self.host_listbox.yview)
        self.host_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.host_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.host_listbox.bind(
            "<<ListboxSelect>>",
            lambda e: self._select_cb and self._select_cb(
                self.host_listbox.curselection()[0] if self.host_listbox.curselection() else None)
        )

    def _build_detail_panel(self):
        panel = tk.Frame(self.root)
        panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.fields: dict[str, tk.Entry] = {}
        for field in ["Host", "HostName", "User", "Port"] + EXTRA_FIELDS:
            tk.Label(panel, text=field).pack(anchor="w")
            entry = tk.Entry(panel)
            entry.pack(fill=tk.X, pady=(0, 5))
            self.fields[field] = entry

        # Contraseña
        tk.Label(panel, text=t("password")).pack(anchor="w")
        pwd_frame = tk.Frame(panel)
        pwd_frame.pack(fill=tk.X, pady=(0,5))
        self.password_entry = tk.Entry(pwd_frame, show="*")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(pwd_frame, text=t("mostrar_contrasena"), command=self._toggle_password).pack(side=tk.LEFT, padx=(5,0))
        self._pwd_shown = False
        self.clear_pwd_var = tk.BooleanVar(value=False)
        tk.Checkbutton(panel, text=t("borrar_contrasena"), variable=self.clear_pwd_var).pack(anchor="w")

        # IdentityFiles
        tk.Label(panel, text=t("identityfile") + " (uno por línea)").pack(anchor="w")
        self.identityfile_text = tk.Text(panel, height=4)
        self.identityfile_text.pack(fill=tk.X, pady=(0,5))
        tk.Button(
            panel, text=t("clave_ssh"),
            command=self._on_select_identity_file
        ).pack(pady=(0,5))

        # Botones de acción
        btn_frame = tk.Frame(panel)
        btn_frame.pack(fill=tk.X, pady=(10,0))
        actions = [
            (t("nuevo"), "_new_cb"), (t("guardar"), "_save_cb"),
            (t("eliminar"), "_delete_cb"), (t("restaurar_backup"), "_restore_cb"),
            (t("copiar_ssh"), "_copy_cb"), (t("test_ssh"), "_test_cb"),
            (t("exportar_json"), "_export_cb"), (t("importar_json"), "_import_cb")
        ]
        self._buttons: List[tk.Button] = []
        for text, cb_attr in actions:
            btn = tk.Button(
                btn_frame,
                text=text,
                command=lambda attr=cb_attr: (getattr(self, attr)() if getattr(self, attr) else None)
            )
            btn.pack(side=tk.LEFT, padx=5, pady=2)
            self._buttons.append(btn)

    def _toggle_password(self):
        if self._pwd_shown:
            self.password_entry.config(show="*")
            self._pwd_shown = False
        else:
            self.password_entry.config(show="")
            self._pwd_shown = True

    def set_password(self, pwd: Optional[str]) -> None:
        if pwd is None:
            return
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, pwd)

    def _on_select_identity_file(self):
        path = filedialog.askopenfilename(
            title=t("seleccionar_clave"),
            filetypes=[(t("archivos_clave"), "*.pem *.key *.pub *.id_rsa"), (t("todos_los_archivos"), "*.*")]
        )
        if path:
            current = self.identityfile_text.get("1.0", tk.END)
            if path not in current:
                self.identityfile_text.insert(tk.END, path + "\n")

    def _build_status_bar(self):
        self.status_label = tk.Label(self.root, text="", fg="green")
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

    def populate_fields(self, host: Host):
        self.clear_fields()
        field_map = {
            'Host': 'alias',
            'HostName': 'host_name',
            'User': 'user',
            'Port': 'port',
            'ProxyJump': 'proxy_jump',
            'LocalForward': 'local_forward',
            'RemoteForward': 'remote_forward',
            'ServerAliveInterval': 'server_alive_interval'
        }
        for key, entry in self.fields.items():
            attr = field_map.get(key, key.lower())
            value = getattr(host, attr, None)
            if value is not None:
                entry.insert(0, str(value))
        for p in host.identity_files:
            self.identityfile_text.insert(tk.END, str(p) + "\n")
        self.clear_pwd_var.set(False)

    def set_readonly(self, readonly: bool):
        state = 'disabled' if readonly else 'normal'
        for entry in self.fields.values():
            entry.config(state=state)
        self.password_entry.config(state=state)
        self.identityfile_text.config(state=state)
        for btn in self._buttons:
            btn.config(state=state)

    def on_new(self, callback: Callable[[], None]): self._new_cb = callback
    def on_save(self, callback: Callable[[], None]): self._save_cb = callback
    def on_delete(self, callback: Callable[[], None]): self._delete_cb = callback
    def on_restore(self, callback: Callable[[], None]): self._restore_cb = callback
    def on_search(self, callback: Callable[[str], None]): self._search_cb = callback
    def on_select(self, callback: Callable[[Optional[int]], None]): self._select_cb = callback
    def on_copy(self, callback: Callable[[], None]): self._copy_cb = callback
    def on_test(self, callback: Callable[[], None]): self._test_cb = callback
    def on_export(self, callback: Callable[[], None]): self._export_cb = callback
    def on_import(self, callback: Callable[[], None]): self._import_cb = callback
    def on_language_change(self, callback: Callable[[str], None]): self._lang_cb = callback
    def on_toggle_readonly(self, callback: Callable[[bool], None]): self._toggle_readonly_cb = callback

    def update_host_list(self, hosts: List[Host]):
        self.host_listbox.delete(0, tk.END)
        for host in hosts:
            self.host_listbox.insert(tk.END, host.alias)

    def clear_fields(self):
        for entry in self.fields.values():
            entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.clear_pwd_var.set(False)
        self.identityfile_text.delete("1.0", tk.END)

    def get_form_data(self) -> Optional[dict]:
        data: dict = {}
        alias = self.fields['Host'].get().strip()
        if not alias:
            return None
        for key, entry in self.fields.items():
            val = entry.get().strip()
            if val:
                data[key] = val
        pwd_val = self.password_entry.get().strip()
        if self.clear_pwd_var.get():
            data['ClearPassword'] = True
        elif pwd_val:
            data['Password'] = pwd_val
        lines = [l.strip() for l in self.identityfile_text.get("1.0", tk.END).splitlines() if l.strip()]
        if lines:
            data['IdentityFile'] = lines
        return data

    def copy_to_clipboard(self, text: str):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()

    def show_status(self, msg: str):
        self.status_label.config(text=msg, fg="green")

    def show_error(self, title: str, msg: str):
        messagebox.showerror(title, msg)
        self.show_status("")

    def show_info(self, title: str, msg: str):
        messagebox.showinfo(title, msg)
        self.show_status("")
