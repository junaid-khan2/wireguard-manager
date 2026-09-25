from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import WireGuardClient
<<<<<<< HEAD
from app.services.wireguard import WireGuardService, WireGuardError
from app.services.xray import XrayService, XrayError
=======
from app.services.wireguard import WireGuardService
>>>>>>> dbc1faef7abfbbd7ad65a47025adad93c621d131


class ClientService:
    def __init__(self, db: Session):
        self.db = db
        self.wireguard = WireGuardService()
        self.xray = XrayService()

    def create_client(self, name: str, mode: str = "wireguard") -> dict:
        existing = self.db.scalar(
            select(WireGuardClient).where(WireGuardClient.name == name)
        )
<<<<<<< HEAD
        if existing:
            raise ValueError("A client with this name already exists")
=======

        if existing_client:
            raise ValueError(
                "A client with this name already exists"
            )
>>>>>>> dbc1faef7abfbbd7ad65a47025adad93c621d131

        private_key, public_key = (
            self.wireguard.generate_key_pair()
        )

        used_ips = {
            c.vpn_ip
            for c in self.db.scalars(select(WireGuardClient)).all()
        }
<<<<<<< HEAD
        client_ip = self.wireguard.get_next_client_ip(used_ips)
=======

        client_ip = (
            self.wireguard.get_next_client_ip(
                used_ips
            )
        )
>>>>>>> dbc1faef7abfbbd7ad65a47025adad93c621d131

        vless_uuid = None
        if mode == "vless":
            vless_uuid = self.xray.generate_uuid()

        client = WireGuardClient(
            name=name,
            public_key=public_key,
            vpn_ip=client_ip,
            vless_uuid=vless_uuid,
        )

        self.db.add(client)

        try:
<<<<<<< HEAD
            if mode == "vless":
                self.xray.add_client(
                    user_uuid=vless_uuid,
                    email=name,
                )
                self.xray.reload()
            else:
                self.wireguard.append_peer(
                    client_public_key=public_key,
                    client_ip=client_ip,
                )
                self.wireguard.reload()

        except (WireGuardError, XrayError):
            self.db.delete(client)
            self.db.commit()
            raise

        return {
            "client": client,
            "private_key": private_key,
            "mode": mode,
        }

    def delete_client(self, client_id: int) -> WireGuardClient:
        client = self.db.get(WireGuardClient, client_id)
=======
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

>>>>>>> dbc1faef7abfbbd7ad65a47025adad93c621d131
        if not client:
            raise ValueError(
                "Client not found"
            )

<<<<<<< HEAD
        try:
            self.wireguard.remove_peer(client.public_key)
            self.wireguard.reload()
        except WireGuardError:
            pass

        if client.vless_uuid:
            try:
                self.xray.remove_client(client.vless_uuid)
                self.xray.reload()
            except XrayError:
                pass
=======
        public_key = client.public_key
>>>>>>> dbc1faef7abfbbd7ad65a47025adad93c621d131

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
