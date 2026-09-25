import json
import subprocess
import uuid as uuid_lib
from pathlib import Path

from app.config import settings


class XrayError(Exception):
    pass


class XrayService:
    def __init__(self):
        self.config_path = Path(settings.xray_config_path)

    def generate_uuid(self) -> str:
        return str(uuid_lib.uuid4())

    def _read_config(self) -> dict:
        if not self.config_path.exists():
            raise XrayError(f"Xray config not found: {self.config_path}")
        return json.loads(self.config_path.read_text(encoding="utf-8"))

    def _write_config(self, cfg: dict) -> None:
        self.config_path.write_text(
            json.dumps(cfg, indent=2),
            encoding="utf-8",
        )

    def add_client(self, user_uuid: str, email: str) -> None:
        cfg = self._read_config()
        inbound = cfg["inbounds"][0]
        clients = inbound["settings"]["clients"]

        if any(c["id"] == user_uuid for c in clients):
            return

        clients.append({
            "id": user_uuid,
            "email": email,
            "level": 0,
        })

        self._write_config(cfg)

    def remove_client(self, user_uuid: str) -> None:
        cfg = self._read_config()
        inbound = cfg["inbounds"][0]

        inbound["settings"]["clients"] = [
            c for c in inbound["settings"]["clients"]
            if c["id"] != user_uuid
        ]

        self._write_config(cfg)

    def reload(self) -> None:
        try:
            subprocess.run(
                ["systemctl", "restart", "xray"],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            raise XrayError(
                exc.stderr.strip() or "Failed to reload Xray"
            ) from exc