import os
import re

CONFIG_PATH = os.path.expanduser("~/.ssh/config")
BACKUP_PATH = CONFIG_PATH + ".bak"

def is_valid_hostname_or_ip(value):
    hostname_regex = re.compile(r'^[a-zA-Z0-9.-]+$')
    ip_regex = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    return bool(hostname_regex.match(value) or ip_regex.match(value))

def load_config():
    if not os.path.exists(CONFIG_PATH):
        open(CONFIG_PATH, 'a').close()

    with open(CONFIG_PATH, 'r') as f:
        lines = f.readlines()

    hosts = []
    current = {}
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("Host "):
            if current:
                hosts.append(current)
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
        hosts.append(current)

    return hosts

def write_config(hosts):
    if os.path.exists(CONFIG_PATH):
        os.rename(CONFIG_PATH, BACKUP_PATH)
    else:
        open(CONFIG_PATH, 'a').close()

    with open(CONFIG_PATH, 'w') as f:
        for host in hosts:
            f.write(f"Host {host.get('Host')}\n")
            for key in ["HostName", "User", "Port", "ProxyJump", "LocalForward", "RemoteForward", "ServerAliveInterval"]:
                if key in host:
                    f.write(f"    {key} {host[key]}\n")
            if "IdentityFile" in host:
                identities = host["IdentityFile"]
                if isinstance(identities, str):
                    identities = [identities]
                for identity in identities:
                    f.write(f"    IdentityFile {identity}\n")
            f.write("\n")

def restore_backup():
    if os.path.exists(BACKUP_PATH):
        os.replace(BACKUP_PATH, CONFIG_PATH)
        return True
    return False
