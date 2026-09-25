import fcntl
import ipaddress
import os
import re
import shutil
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

        self.lock_path = Path(
            f"/run/{self.interface}-manager.lock"
        )

        self.backup_dir = self.config_path.parent / "backups"

        self.client_config_dir = (
            Path("/opt/wireguard-manager/data/clients")
        )

    # ---------------------------------------------------------
    # Command execution
    # ---------------------------------------------------------

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
            stderr = exc.stderr.strip()
            stdout = exc.stdout.strip()

            message = stderr or stdout or "Command failed"

            raise WireGuardError(
                f"Command failed: {' '.join(command)}: {message}"
            ) from exc

    # ---------------------------------------------------------
    # Locking
    # ---------------------------------------------------------

    def _acquire_lock(self):
        self.lock_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        lock_file = open(self.lock_path, "w")

        fcntl.flock(
            lock_file.fileno(),
            fcntl.LOCK_EX,
        )

        return lock_file

    def _release_lock(self, lock_file):
        try:
            fcntl.flock(
                lock_file.fileno(),
                fcntl.LOCK_UN,
            )
        finally:
            lock_file.close()

    # ---------------------------------------------------------
    # Key generation
    # ---------------------------------------------------------

    def generate_private_key(self) -> str:
        return self.run_command(
            ["wg", "genkey"]
        )

    def generate_public_key(
        self,
        private_key: str,
    ) -> str:
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
                exc.stderr.strip()
                or "Failed to generate public key"
            ) from exc

    def generate_key_pair(self) -> tuple[str, str]:
        private_key = self.generate_private_key()
        public_key = self.generate_public_key(
            private_key
        )

        return private_key, public_key

    # ---------------------------------------------------------
    # Server configuration
    # ---------------------------------------------------------

    def read_config(self) -> str:
        if not self.config_path.exists():
            raise WireGuardError(
                "WireGuard configuration does not exist: "
                f"{self.config_path}"
            )

        return self.config_path.read_text(
            encoding="utf-8"
        )

    def _backup_config(self) -> Path:
        if not self.config_path.exists():
            raise WireGuardError(
                "Cannot backup missing WireGuard config"
            )

        self.backup_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        backup_path = (
            self.backup_dir
            / f"wg0.conf.{os.getpid()}.{int(__import__('time').time())}.bak"
        )

        shutil.copy2(
            self.config_path,
            backup_path,
        )

        os.chmod(
            backup_path,
            0o600,
        )

        return backup_path

    def write_config_atomically(
        self,
        config: str,
    ) -> None:
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
            temp_file.flush()
            os.fsync(temp_file.fileno())

            temp_path = Path(
                temp_file.name
            )

        os.chmod(
            temp_path,
            0o600,
        )

        temp_path.replace(
            self.config_path
        )

    def validate_config(
        self,
        config: str,
    ) -> None:
        self.config_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        temp_path = (
            self.config_path.parent
            / "wg0test.conf"
        )

        try:
            with open(
                temp_path,
                "w",
                encoding="utf-8",
            ) as temp_file:
                temp_file.write(config)
                temp_file.flush()
                os.fsync(temp_file.fileno())

            os.chmod(
                temp_path,
                0o600,
            )

            self.run_command(
                [
                    "wg-quick",
                    "strip",
                    str(temp_path),
                ]
            )

        finally:
            temp_path.unlink(
                missing_ok=True
            )

    # ---------------------------------------------------------
    # VPN IP allocation
    # ---------------------------------------------------------





    def get_next_client_ip(
        self,
        used_ips: set[str],
    ) -> str:
        network = ipaddress.ip_network(
            settings.wireguard_network,
            strict=False,
        )

        for host in network.hosts():
            candidate = str(host)

            if (
                candidate
                == settings.wireguard_server_vpn_ip
            ):
                continue

            if candidate not in used_ips:
                return candidate

        raise WireGuardError(
            "No free VPN IP addresses remain"
        )

    # ---------------------------------------------------------
    # Peer handling
    # ---------------------------------------------------------

    def _peer_exists(
        self,
        client_public_key: str,
    ) -> bool:
        try:
            output = self.run_command(
                [
                    "wg",
                    "show",
                    self.interface,
                    "peers",
                ]
            )

            return client_public_key in output.splitlines()

        except WireGuardError:
            return False

    def append_peer(
        self,
        client_public_key: str,
        client_ip: str,
    ) -> None:
        lock = self._acquire_lock()

        try:
            if self._peer_exists(
                client_public_key
            ):
                raise WireGuardError(
                    "WireGuard peer already exists"
                )

            config = self.read_config()

            peer_block = (
                "\n\n"
                "[Peer]\n"
                "# Managed client\n"
                f"PublicKey = {client_public_key}\n"
                f"AllowedIPs = {client_ip}/32\n"
            )

            new_config = (
                config.rstrip()
                + peer_block
                + "\n"
            )

            # Validate BEFORE touching production config.
            self.validate_config(
                new_config
            )

            # Backup current production config.
            self._backup_config()

            # Persist configuration.
            self.write_config_atomically(
                new_config
            )

            try:
                # Apply ONLY the new peer to the
                # running WireGuard interface.
                self.run_command(
                    [
                        "wg",
                        "set",
                        self.interface,
                        "peer",
                        client_public_key,
                        "allowed-ips",
                        f"{client_ip}/32",
                    ]
                )

            except Exception:
                # Restore config if runtime application failed.
                self.write_config_atomically(
                    config
                )
                raise

        finally:
            self._release_lock(lock)

    def remove_peer(
        self,
        client_public_key: str,
    ) -> None:
        lock = self._acquire_lock()

        try:
            config = self.read_config()

            pattern = re.compile(
                r"\n\[Peer\]\n"
                r"(?:[^\[]|\[(?!Peer\]))*",
                re.MULTILINE,
            )

            blocks = pattern.findall(
                config
            )

            target_block = None
            remaining_blocks = []

            for block in blocks:
                if (
                    f"PublicKey = {client_public_key}"
                    in block
                ):
                    target_block = block
                else:
                    remaining_blocks.append(
                        block
                    )

            if target_block is None:
                raise WireGuardError(
                    "WireGuard peer not found"
                )

            base_config = config.split(
                "[Peer]",
                1,
            )[0].rstrip()

            new_config = base_config

            for block in remaining_blocks:
                new_config += (
                    "\n"
                    + block.rstrip()
                    + "\n"
                )

            # Validate BEFORE touching production config.
            self.validate_config(
                new_config
            )

            self._backup_config()

            self.write_config_atomically(
                new_config
            )

            try:
                # Remove peer from running interface.
                self.run_command(
                    [
                        "wg",
                        "set",
                        self.interface,
                        "peer",
                        client_public_key,
                        "remove",
                    ]
                )

            except Exception:
                self.write_config_atomically(
                    config
                )
                raise

        finally:
            self._release_lock(lock)

    # ---------------------------------------------------------
    # Client configuration
    # ---------------------------------------------------------

    def save_client_config(
        self,
        client_id: int,
        client_name: str,
        config: str,
    ) -> Path:
        self.client_config_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        safe_name = re.sub(
            r"[^a-zA-Z0-9._-]+",
            "_",
            client_name,
        ).strip(
            "._-"
        )

        if not safe_name:
            safe_name = "client"

        filename = (
            f"{client_id}-{safe_name}.conf"
        )

        path = (
            self.client_config_dir
            / filename
        )

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=self.client_config_dir,
            delete=False,
        ) as temp_file:
            temp_file.write(config)
            temp_file.flush()
            os.fsync(temp_file.fileno())

            temp_path = Path(
                temp_file.name
            )

        os.chmod(
            temp_path,
            0o600,
        )

        temp_path.replace(
            path
        )

        return path

    def delete_client_config(
        self,
        client_id: int,
    ) -> None:
        pattern = (
            self.client_config_dir
            / f"{client_id}-*.conf"
        )

        for path in self.client_config_dir.glob(
            pattern.name
        ):
            path.unlink(
                missing_ok=True
            )

    def generate_client_config(
        self,
        client_private_key: str,
        server_public_key: str,
        client_ip: str,
        full_tunnel: bool = True,
    ) -> str:
        allowed_ips = (
            "0.0.0.0/0"
            if full_tunnel
            else "10.104.5.0/24"
        )

        return f"""[Interface]
PrivateKey = {client_private_key}
Address = {client_ip}/32
DNS = {settings.wireguard_dns}

[Peer]
PublicKey = {server_public_key}
Endpoint = {settings.wireguard_server_public_ip}:{settings.wireguard_server_port}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""

    # ---------------------------------------------------------
    # Server state
    # ---------------------------------------------------------

    def reload(self) -> None:
        """
        Kept for compatibility.

        Client operations should NOT use this method.
        """
        self.run_command(
            [
                "systemctl",
                "restart",
                f"wg-quick@{self.interface}",
            ]
        )
