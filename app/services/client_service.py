from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import WireGuardClient
from app.services.wireguard import WireGuardService, WireGuardError


class ClientService:
    def __init__(self, db: Session):
        self.db = db
        self.wireguard = WireGuardService()

    def create_client(self, name: str) -> dict:
        existing_client = self.db.scalar(
            select(WireGuardClient).where(
                WireGuardClient.name == name
            )
        )

        if existing_client:
            raise ValueError("A client with this name already exists")

        private_key, public_key = self.wireguard.generate_key_pair()

        used_ips = {
            client.vpn_ip
            for client in self.db.scalars(
                select(WireGuardClient)
            ).all()
        }

        client_ip = self.wireguard.get_next_client_ip(used_ips)

        client = WireGuardClient(
            name=name,
            public_key=public_key,
            vpn_ip=client_ip,
        )

        self.db.add(client)
        self.db.commit()
        self.db.refresh(client)

        try:
            self.wireguard.append_peer(
                client_public_key=public_key,
                client_ip=client_ip,
            )

            self.wireguard.reload()

        except Exception:
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

        self.wireguard.remove_peer(client.public_key)
        self.wireguard.reload()

        self.db.delete(client)
        self.db.commit()

        return client