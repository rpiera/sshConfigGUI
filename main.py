import tkinter as tk
import json
from pathlib import Path
from tkinter import simpledialog, messagebox

from settings import APP_SETTINGS_PATH
from i18n import load_language, t
from view import SSHConfigView
from controller import SSHConfigController
from auth import AuthService


def load_app_settings() -> dict:
    """
    Carga los settings de la aplicación (layout, idioma).
    """
    try:
        with APP_SETTINGS_PATH.open('r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_app_settings(settings: dict) -> None:
    """
    Guarda los settings de la aplicación.
    """
    APP_SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with APP_SETTINGS_PATH.open('w', encoding='utf-8') as f:
        json.dump(settings, f, indent=2)


def authenticate(root: tk.Tk, auth: AuthService) -> bool:
    """
    Gestiona la autenticación con contraseña maestra.
    """
    pw_actual = auth.get_password()
    if pw_actual is None:
        nueva = simpledialog.askstring(t("crear_contrasena"), t("establece_contrasena"), show='*')
        if nueva:
            auth.store_password(auth.master_entry, nueva)
            messagebox.showinfo(t("contrasena_guardada"), t("contrasena_guardada"))
        else:
            messagebox.showerror(t("cancelado"), t("no_contrasena"))
            return False
    else:
        pw = simpledialog.askstring(t("acceso_protegido"), t("introduce_contrasena"), show='*')
        if pw != pw_actual:
            messagebox.showerror(t("acceso_denegado"), t("contrasena_incorrecta"))
            return False
    return True


if __name__ == '__main__':
    # Cargar settings previos
    app_settings = load_app_settings()
    lang = app_settings.get('lang', 'es')
    load_language(lang)

    # Inicializar ventana y ocultar hasta autenticar
    root = tk.Tk()
    root.withdraw()

    # Autenticación
    auth = AuthService()
    auth.ensure_ready()
    if not authenticate(root, auth):
        root.destroy()
        exit(1)

    # Mostrar interfaz
    root.deiconify()
    view = SSHConfigView(root)

    # Restaurar tamaño de ventana
    if 'window_size' in app_settings:
        root.geometry(app_settings['window_size'])

    # Iniciar controlador
    controller = SSHConfigController(view)

    # Guardar preferencia de idioma al cambiar
    view.on_language_change(lambda lang: (
        app_settings.update(lang=lang),
        save_app_settings(app_settings)
    ))

    # Al cerrar: guardar settings y destruir
    def on_close():
        app_settings['window_size'] = root.geometry()
        save_app_settings(app_settings)
        root.destroy()

    root.protocol('WM_DELETE_WINDOW', on_close)
    root.mainloop()
