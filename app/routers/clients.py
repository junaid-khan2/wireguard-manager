from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import WireGuardClient
from app.schemas import (
    ClientConfigResponse,
    ClientCreateRequest,
    ClientResponse,
    VlessConfig,
)
from app.services.client_service import ClientService
from app.services.wireguard import WireGuardService


router = APIRouter(
    prefix="/api/clients",
    tags=["WireGuard Clients"],
)


def build_vless_uri(
    uuid: str,
    address: str,
    port: int,
    path: str,
    sni: str,
    remark: str,
) -> str:
    params = {
        "encryption": "none",
        "security": "tls",
        "sni": sni,
        "type": "ws",
        "host": sni,
        "path": path,
    }
    query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
    return f"vless://{uuid}@{address}:{port}?{query}#{quote(remark)}"


@router.post(
    "",
    response_model=ClientConfigResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_client(
    payload: ClientCreateRequest,
    db: Session = Depends(get_db),
):
    service = ClientService(db)

    try:
        result = service.create_client(payload.name)
        client = result["client"]
        private_key = result["private_key"]

        # ---------- WireGuard config ----------
        wireguard = WireGuardService()
        server_public_key = settings.wireguard_server_public_key

        if not server_public_key:
            raise RuntimeError(
                "WIREGUARD_SERVER_PUBLIC_KEY is not configured"
            )

        wg_config = wireguard.generate_client_config(
            client_private_key=private_key,
            server_public_key=server_public_key,
            client_ip=client.vpn_ip,
            full_tunnel=True,
        )

        # ---------- VLESS config ----------
        if not client.vless_uuid:
            raise RuntimeError("VLESS UUID missing on client")

        uri = build_vless_uri(
            uuid=client.vless_uuid,
            address=settings.vless_address,
            port=settings.vless_port,
            path=settings.vless_path,
            sni=settings.vless_sni,
            remark=client.name,
        )

        vless = VlessConfig(
            uuid=client.vless_uuid,
            address=settings.vless_address,
            port=settings.vless_port,
            network=settings.vless_network,
            path=settings.vless_path,
            security=settings.vless_security,
            sni=settings.vless_sni,
            uri=uri,
        )

        return {
            "name": client.name,
            "vpn_ip": client.vpn_ip,
            "config": wg_config,
            "vless": vless,
        }

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Failed to create client",
        ) from exc


@router.get("", response_model=list[ClientResponse])
def list_clients(db: Session = Depends(get_db)):
    return db.scalars(
        select(WireGuardClient).order_by(WireGuardClient.id.desc())
    ).all()


@router.delete("/{client_id}")
def delete_client(client_id: int, db: Session = Depends(get_db)):
    service = ClientService(db)
    try:
        service.delete_client(client_id)
        return {"message": "Client removed successfully"}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Failed to delete client",
        ) from exc
