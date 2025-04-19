import re
from typing import Union, Sequence, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from models import Host

# Patrones para validación de hostname
_hostname_pattern = re.compile(r"^[a-zA-Z0-9.-]+$")


def is_valid_ip(ip: str) -> bool:
    """
    Comprueba si la cadena es una IP IPv4 válida, con octetos de 0 a 255.
    """
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            n = int(part)
        except ValueError:
            return False
        if not 0 <= n <= 255:
            return False
    return True


def is_valid_hostname(hostname: str) -> bool:
    """
    Comprueba si la cadena es un nombre de host válido.
    """
    return bool(_hostname_pattern.match(hostname))


def is_valid_hostname_or_ip(value: str) -> bool:
    """
    Comprueba si es un hostname o IP válida.
    """
    if not value:
        return False
    return is_valid_ip(value) or is_valid_hostname(value)


def is_valid_port(port: Union[str, int]) -> bool:
    """
    Comprueba si el puerto es un entero entre 1 y 65535.
    """
    try:
        p = int(port)
        return 1 <= p <= 65535
    except (TypeError, ValueError):
        return False


def detect_duplicate_alias(hosts: Sequence["Host"], alias: str, exclude_index: Optional[int] = None) -> bool:
    """
    Comprueba si ya existe un Host con el mismo alias en la lista, excluyendo índice opcional.
    """
    for idx, host in enumerate(hosts):
        if exclude_index is not None and idx == exclude_index:
            continue
        if host.alias == alias:
            return True
    return False
