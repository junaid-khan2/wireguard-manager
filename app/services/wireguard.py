import ipaddress
import os
import re
import subprocess
import tempfile
from pathlib import Path

from app.config import settings


class WireGuardError(Exception):
    pass


class WireGuardService:
    def __init__(self):
        self.config_path = Path(settings.wireguard_config_path)

    def run_command(self, command: list[str]) -> str:
        try:
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
            )

            return result.stdout.strip()

        except subprocess.CalledProcessError as exc:
            raise WireGuardError(
                exc.stderr.strip() or "WireGuard command failed"
            ) from exc

    def generate_private_key(self) -> str:
        return self.run_command(["wg", "genkey"])

    def generate_public_key(self, private_key: str) -> str:
        process = subprocess.run(
            ["wg", "pubkey"],
            input=private_key,
            capture_output=True,
            text=True,
            check=True,
        )

        return process.stdout.strip()

    def generate_key_pair(self) -> tuple[str, str]:
        private_key = self.generate_private_key()
        public_key = self.generate_public_key(private_key)

        return private_key, public_key

    def read_config(self) -> str:
        if not self.config_path.exists():
            raise WireGuardError(
                f"WireGuard configuration does not exist: {self.config_path}"
            )

        return self.config_path.read_text(encoding="utf-8")

    def write_config_atomically(self, config: str) -> None:
        self.config_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=self.config_path.parent,
            delete=False,
        ) as temp_file:
            temp_file.write(config)
            temp_path = Path(temp_file.name)

        os.chmod(temp_path, 0o600)
        temp_path.replace(self.config_path)

    def get_next_client_ip(self, used_ips: set[str]) -> str:
        network = ipaddress.ip_network(
            settings.wireguard_network,
            strict=False,
        )

        for host in network.hosts():
            candidate = str(host)

            if candidate == settings.wireguard_server_vpn_ip:
                continue

            if candidate not in used_ips:
                return candidate

        raise WireGuardError("No free VPN IP addresses remain")

    def append_peer(
        self,
        client_public_key: str,
        client_ip: str,
    ) -> None:
        config = self.read_config()

        peer_block = f"""

[Peer]
# Managed client
PublicKey = {client_public_key}
AllowedIPs = {client_ip}/32
"""

        self.write_config_atomically(config.rstrip() + peer_block + "\n")

    def remove_peer(self, client_public_key: str) -> None:
        config = self.read_config()

        pattern = re.compile(
            r"\n\[Peer\]\n"
            r"(?:.*\n)*?"
            r"(?=^\[Peer\]|\Z)",
            re.MULTILINE,
        )

        blocks = pattern.findall(config)
        remaining_blocks = []

        for block in blocks:
            if f"PublicKey = {client_public_key}" not in block:
                remaining_blocks.append(block)

        if not blocks:
            raise WireGuardError("No peer blocks found in WireGuard config")

        base_config = config.split("[Peer]", 1)[0].rstrip()

        new_config = base_config

        for block in remaining_blocks:
            new_config += "\n" + block.rstrip() + "\n"

        self.write_config_atomically(new_config)

    def reload(self) -> None:
        self.run_command(
            [
                "systemctl",
                "restart",
                f"wg-quick@{settings.wireguard_interface}",
            ]
        )

    def generate_client_config(
        self,
        client_private_key: str,
        server_public_key: str,
        client_ip: str,
        full_tunnel: bool = True,
    ) -> str:
        allowed_ips = "0.0.0.0/0" if full_tunnel else "10.104.5.0/24"

        return f"""[Interface]
PrivateKey = {client_private_key}
Address = {client_ip}/24
DNS = {settings.wireguard_dns}

[Peer]
PublicKey = {server_public_key}
Endpoint = {settings.wireguard_server_public_ip}:{settings.wireguard_server_port}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""