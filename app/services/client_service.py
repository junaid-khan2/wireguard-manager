from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import WireGuardClient
from app.services.wireguard import WireGuardService


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
            raise ValueError(
                "A client with this name already exists"
            )

        private_key, public_key = (
            self.wireguard.generate_key_pair()
        )

        used_ips = {
            client.vpn_ip
            for client in self.db.scalars(
                select(WireGuardClient)
            ).all()
        }

        client_ip = (
            self.wireguard.get_next_client_ip(
                used_ips
            )
        )

        client = WireGuardClient(
            name=name,
            public_key=public_key,
            vpn_ip=client_ip,
        )

        self.db.add(client)

        try:
            # Flush so SQLAlchemy obtains the client ID
            # without permanently committing yet.
            self.db.flush()

            # Add peer to WireGuard.
            self.wireguard.append_peer(
                client_public_key=public_key,
                client_ip=client_ip,
            )

            # Generate client configuration.
            client_config = (
                self.wireguard.generate_client_config(
                    client_private_key=private_key,
                    server_public_key=(
                        __import__(
                            "app.config",
                            fromlist=["settings"],
                        )
                        .settings
                        .wireguard_server_public_key
                    ),
                    client_ip=client_ip,
                    full_tunnel=True,
                )
            )

            # Save client config separately.
            config_path = (
                self.wireguard.save_client_config(
                    client_id=client.id,
                    client_name=client.name,
                    config=client_config,
                )
            )

            # Only now permanently commit DB.
            self.db.commit()

            self.db.refresh(client)

            return {
                "client": client,
                "private_key": private_key,
                "config": client_config,
                "config_path": str(config_path),
            }

        except Exception:
            self.db.rollback()

            # If the peer was successfully added before a later
            # operation failed, attempt to remove it.
            try:
                self.wireguard.remove_peer(
                    public_key
                )
            except Exception:
                # The original exception is more useful to the caller.
                pass

            try:
                self.wireguard.delete_client_config(
                    client.id
                )
            except Exception:
                pass

            raise

    def delete_client(
        self,
        client_id: int,
    ) -> WireGuardClient:
        client = self.db.get(
            WireGuardClient,
            client_id,
        )

        if not client:
            raise ValueError(
                "Client not found"
            )

        public_key = client.public_key

        try:
            # Remove from running WireGuard and
            # persistent server configuration first.
            self.wireguard.remove_peer(
                public_key
            )

            # Remove database record only after
            # WireGuard succeeds.
            self.db.delete(client)
            self.db.commit()

            # Delete generated client config.
            self.wireguard.delete_client_config(
                client_id
            )

            return client

        except Exception:
            self.db.rollback()
            raise
