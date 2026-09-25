import ipaddress
import os
import subprocess
import tempfile
from pathlib import Path

from app.config import settings


class WireGuardError(Exception):
    pass


class WireGuardService:
    def __init__(self):
        self.interface = settings.wireguard_interface
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
        try:
            process = subprocess.run(
                ["wg", "pubkey"],
                input=private_key,
                capture_output=True,
                text=True,
                check=True,
            )
            return process.stdout.strip()
        except subprocess.CalledProcessError as exc:
            raise WireGuardError(
                exc.stderr.strip() or "Failed to generate public key"
            ) from exc

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
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
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
        peer_block = (
            "\n\n"
            "[Peer]\n"
            "# Managed client\n"
            f"PublicKey = {client_public_key}\n"
            f"AllowedIPs = {client_ip}/32\n"
        )
        self.write_config_atomically(config.rstrip() + peer_block + "\n")

    def remove_peer(self, client_public_key: str) -> None:
        config = self.read_config()

        if "[Peer]" not in config:
            raise WireGuardError("No peer blocks found in WireGuard config")

        parts = config.split("[Peer]")
        header = parts[0].rstrip()

        kept_peers = []
        removed = False

        for block in parts[1:]:
            if f"PublicKey = {client_public_key}" in block:
                removed = True
                continue
            kept_peers.append(block.rstrip())

        if not removed:
            raise WireGuardError("Peer not found in WireGuard config")

        new_config = header
        for block in kept_peers:
            new_config += "\n\n[Peer]" + block
        new_config += "\n"

        self.write_config_atomically(new_config)

    def reload(self) -> None:
        self.run_command(
            [
                "systemctl",
                "restart",
                f"wg-quick@{self.interface}",
            ]
        )

    def generate_client_config(
        self,
        client_private_key: str,
        server_public_key: str,
        client_ip: str,
        full_tunnel: bool = True,
    ) -> str:
        if full_tunnel:
            allowed_ips = "0.0.0.0/0, ::/0"
        else:
            allowed_ips = settings.wireguard_network

        return f"""[Interface]
PrivateKey = {client_private_key}
Address = {client_ip}/32
DNS = {settings.wireguard_dns}
MTU = {settings.wireguard_mtu}

[Peer]
PublicKey = {server_public_key}
Endpoint = {settings.wireguard_server_public_ip}:{settings.wireguard_server_port}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""
