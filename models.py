from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import validators

@dataclass
class Host:
    """
    Representa una entrada Host en ~/.ssh/config.
    """
    alias: str
    host_name: Optional[str] = None
    user: Optional[str] = None
    port: Optional[int] = None
    proxy_jump: Optional[str] = None
    local_forward: Optional[str] = None
    remote_forward: Optional[str] = None
    server_alive_interval: Optional[int] = None
    identity_files: List[Path] = field(default_factory=list)

    def __post_init__(self):
        # Validar alias siempre presente y válido
        if not self.alias:
            raise ValueError("El alias 'Host' no puede estar vacío.")
        if not validators.is_valid_hostname_or_ip(self.alias):
            raise ValueError(f"Alias inválido: {self.alias}")
        # Validar host_name si existe
        if self.host_name and not validators.is_valid_hostname_or_ip(self.host_name):
            raise ValueError(f"HostName inválido: {self.host_name}")
        # Validar puerto si existe
        if self.port is not None and not validators.is_valid_port(self.port):
            raise ValueError(f"Puerto inválido: {self.port}")

    @classmethod
    def from_dict(cls, data: dict) -> 'Host':
        """
        Crea un Host a partir de un dict obtenido del parser de config.
        """
        # Parse numeric fields
        port = data.get('Port')
        if port is not None:
            try:
                port = int(port)
            except ValueError:
                port = None

        interval = data.get('ServerAliveInterval')
        if interval is not None:
            try:
                interval = int(interval)
            except ValueError:
                interval = None

        # IdentityFile puede ser string o lista
        id_files = data.get('IdentityFile', [])
        if isinstance(id_files, str):
            id_files = [id_files]
        id_paths = [Path(p) for p in id_files]

        return cls(
            alias=data.get('Host', ''),
            host_name=data.get('HostName'),
            user=data.get('User'),
            port=port,
            proxy_jump=data.get('ProxyJump'),
            local_forward=data.get('LocalForward'),
            remote_forward=data.get('RemoteForward'),
            server_alive_interval=interval,
            identity_files=id_paths,
        )

    def to_dict(self) -> dict:
        """
        Convierte el Host a dict para escribir en config.
        """
        result = {'Host': self.alias}
        if self.host_name:
            result['HostName'] = self.host_name
        if self.user:
            result['User'] = self.user
        if self.port is not None:
            result['Port'] = str(self.port)
        if self.proxy_jump:
            result['ProxyJump'] = self.proxy_jump
        if self.local_forward:
            result['LocalForward'] = self.local_forward
        if self.remote_forward:
            result['RemoteForward'] = self.remote_forward
        if self.server_alive_interval is not None:
            result['ServerAliveInterval'] = str(self.server_alive_interval)
        if self.identity_files:
            result['IdentityFile'] = [str(p) for p in self.identity_files]
        return result
