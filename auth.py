import subprocess
from i18n import t

PASS_ENTRY = "sshConfigGUI/master-password"

def ensure_pass_ready():
    import shutil, os
    if not shutil.which("gpg") or not shutil.which("pass"):
        subprocess.run(["sudo", "apt", "update"])
        subprocess.run(["sudo", "apt", "install", "-y", "gnupg2", "pass"])

    result = subprocess.run(["gpg", "--list-keys"], capture_output=True, text=True)
    if "pub" not in result.stdout:
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

    result = subprocess.run(["gpg", "--list-keys", "--with-colons"], capture_output=True, text=True)
    key_id = next((line.split(':')[4] for line in result.stdout.splitlines() if line.startswith("pub")), None)
    if key_id:
        subprocess.run(["pass", "init", key_id])

def get_password_from_pass(entry=PASS_ENTRY):
    try:
        result = subprocess.run(["pass", "show", entry], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None

def store_password_in_pass(entry, password):
    try:
        subprocess.run(["pass", "insert", "-m", "--force", entry], input=password.encode(), check=True)
    except subprocess.CalledProcessError as e:
        print(t("error_guardando_pass").format(e=e))

def delete_password_from_pass(entry):
    try:
        subprocess.run(["pass", "rm", "-f", entry], check=True)
    except subprocess.CalledProcessError as e:
        print(t("error_eliminando_pass").format(e=e))