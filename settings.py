from pathlib import Path

# Paths and constants for sshConfigGUI
HOME = Path.home()

# SSH config file path
SSH_CONFIG_PATH = HOME / ".ssh" / "config"

# Backup directory for sshConfigGUI
BACKUP_DIR = HOME / ".config" / "sshConfigGUI" / "backups"

# Application settings file
APP_SETTINGS_PATH = HOME / ".config" / "sshConfigGUI" / "settings.json"

# Pass entry key for master password
PASS_ENTRY_MASTER = "sshConfigGUI/master-password"