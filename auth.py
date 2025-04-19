import os
import shutil
import subprocess
from typing import Optional

from i18n import t
import settings


def _write_and_generate(batch_filename: str, batch_script: str) -> None:
    """
    Escribe el script de batch para GPG y genera la clave con manejo de limpieza.
    """
    try:
        with open(batch_filename, "w") as f:
            f.write(batch_script)
        subprocess.run(["gpg", "--batch", "--generate-key", batch_filename], check=True)
    finally:
        if os.path.exists(batch_filename):
            os.remove(batch_filename)


class AuthService:
    """
    Servicio para gestionar GPG y pass (contraseñas) para sshConfigGUI.
    """
    def __init__(self, master_entry: str = settings.PASS_ENTRY_MASTER):
        self.master_entry = master_entry

    def ensure_ready(self) -> None:
        """
        Asegura que GPG y pass estén instalados y configurados.
        """
        # Instalar dependencias si no existen
        if not shutil.which("gpg") or not shutil.which("pass"):
            try:
                subprocess.run(["sudo", "apt", "update"], check=True)
                subprocess.run(["sudo", "apt", "install", "-y", "gnupg2", "pass"], check=True)
            except subprocess.CalledProcessError as e:
                print(t("error_instalando_dependencias").format(e=e))
                return

        # Verificar o generar clave GPG
        result = subprocess.run(["gpg", "--list-keys", "--with-colons"], capture_output=True, text=True)
        if not any(line.startswith("pub") for line in result.stdout.splitlines()):
            # Crear clave sin protección
            batch = (
                "%echo Generating key\n"
                "Key-Type: RSA\n"
                "Key-Length: 2048\n"
                "Subkey-Type: RSA\n"
                "Subkey-Length: 2048\n"
                "Name-Real: sshConfigGUI\n"
                "Name-Email: sshconfiggui@example.com\n"
                "Expire-Date: 0\n"
                "%no-protection\n"
                "%commit"
            )
            _write_and_generate("gpg_batch.txt", batch)
            # recargar lista
            result = subprocess.run(["gpg", "--list-keys", "--with-colons"], capture_output=True, text=True)

        # Extraer fingerprint de la clave
        key_id = None
        saw_pub = False
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "pub":
                saw_pub = True
            elif saw_pub and parts[0] == "fpr":
                key_id = parts[9]
                break

        if key_id:
            try:
                subprocess.run(["pass", "init", key_id], check=True)
            except subprocess.CalledProcessError as e:
                print(t("error_inicializando_pass").format(e=e))

    def get_password(self, entry: Optional[str] = None) -> Optional[str]:
        """
        Obtiene la contraseña del almacén 'pass'. Si no existe, retorna None.
        """
        entry = entry or self.master_entry
        try:
            result = subprocess.run(
                ["pass", "show", entry], capture_output=True, text=True, check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None

    def store_password(self, entry: str, password: str) -> None:
        """
        Almacena o actualiza la contraseña en 'pass'.
        """
        try:
            subprocess.run(
                ["pass", "insert", "-m", "--force", entry],
                input=password,
                text=True,
                check=True
            )
        except subprocess.CalledProcessError as e:
            print(t("error_guardando_pass").format(e=e))

    def delete_password(self, entry: str) -> None:
        """
        Elimina la contraseña del almacén 'pass'.
        """
        try:
            subprocess.run(["pass", "rm", "-f", entry], check=True)
        except subprocess.CalledProcessError as e:
            print(t("error_eliminando_pass").format(e=e))
