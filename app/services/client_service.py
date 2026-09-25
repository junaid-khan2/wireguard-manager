from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import WireGuardClient
from app.services.wireguard import WireGuardService, WireGuardError
from app.services.xray import XrayService, XrayError


class ClientService:
    def __init__(self, db: Session):
        self.db = db
        self.wireguard = WireGuardService()
        self.xray = XrayService()

    def create_client(self, name: str, mode: str | None = None) -> dict:
        """
        Create a client with BOTH WireGuard and VLESS access.

        `mode` param is ignored — every client supports both modes now.
        """
        existing = self.db.scalar(
            select(WireGuardClient).where(WireGuardClient.name == name)
        )
        if existing:
            raise ValueError("A client with this name already exists")

        # WireGuard key pair
        private_key, public_key = self.wireguard.generate_key_pair()

        # Next available VPN IP
        used_ips = {
            c.vpn_ip
            for c in self.db.scalars(select(WireGuardClient)).all()
        }
        client_ip = self.wireguard.get_next_client_ip(used_ips)

        # VLESS UUID
        vless_uuid = self.xray.generate_uuid()

        client = WireGuardClient(
            name=name,
            public_key=public_key,
            vpn_ip=client_ip,
            vless_uuid=vless_uuid,
        )

        self.db.add(client)
        self.db.commit()
        self.db.refresh(client)

        # Register both backends
        try:
            self.wireguard.append_peer(
                client_public_key=public_key,
                client_ip=client_ip,
            )
            self.wireguard.reload()
        except WireGuardError as exc:
            self.db.delete(client)
            self.db.commit()
            raise

        try:
            self.xray.add_client(
                user_uuid=vless_uuid,
                email=name,
            )
            self.xray.reload()
        except XrayError:
            # Rollback WireGuard peer too
            try:
                self.wireguard.remove_peer(public_key)
                self.wireguard.reload()
            except WireGuardError:
                pass
            self.db.delete(client)
            self.db.commit()
            raise

        return {
            "client": client,
            "private_key": private_key,
        }

    def delete_client(self, client_id: int) -> WireGuardClient:
        client = self.db.get(WireGuardClient, client_id)
        if not client:
            raise ValueError("Client not found")

        # Remove WireGuard peer
        try:
            self.wireguard.remove_peer(client.public_key)
            self.wireguard.reload()
        except WireGuardError:
            pass

        # Remove VLESS client
        if client.vless_uuid:
            try:
                self.xray.remove_client(client.vless_uuid)
                self.xray.reload()
            except XrayError:
                pass

        self.db.delete(client)
        self.db.commit()

        return client
