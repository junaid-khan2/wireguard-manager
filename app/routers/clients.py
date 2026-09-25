import logging

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
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


logger = logging.getLogger(__name__)


router = APIRouter(
    prefix="/api/clients",
    tags=["WireGuard Clients"],
)


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
        result = service.create_client(
<<<<<<< HEAD
            name=payload.name,
            mode=payload.mode,
        )

        client = result["client"]
        mode = result["mode"]

        if mode == "vless":
            if not client.vless_uuid:
                raise RuntimeError("Failed to generate VLESS UUID")

            return {
                "name": client.name,
                "vpn_ip": client.vpn_ip,
                "config": None,
                "vless": VlessConfig(
                    uuid=client.vless_uuid,
                    address=settings.vless_address,
                    port=settings.vless_port,
                    network=settings.vless_network,
                    path=settings.vless_path,
                    security=settings.vless_security,
                    sni=settings.vless_sni,
                ),
            }

        private_key = result["private_key"]
        wireguard = WireGuardService()

        server_public_key = os.getenv("WIREGUARD_SERVER_PUBLIC_KEY")
        if not server_public_key:
            raise RuntimeError("WIREGUARD_SERVER_PUBLIC_KEY is not configured")

        client_config = wireguard.generate_client_config(
            client_private_key=private_key,
            server_public_key=server_public_key,
            client_ip=client.vpn_ip,
            full_tunnel=True,
        )
=======
            payload.name
        )

        client = result["client"]
>>>>>>> dbc1faef7abfbbd7ad65a47025adad93c621d131

        return {
            "name": client.name,
            "vpn_ip": client.vpn_ip,
<<<<<<< HEAD
            "config": client_config,
            "vless": None,
        }

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
=======
            "config": result["config"],
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

>>>>>>> dbc1faef7abfbbd7ad65a47025adad93c621d131
    except Exception as exc:
        logger.exception(
            "Failed to create WireGuard client: %s",
            exc,
        )

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
<<<<<<< HEAD
        service.delete_client(client_id)
        return {"message": "Client removed successfully"}
=======
        service.delete_client(
            client_id
        )

        return {
            "message": (
                "WireGuard client removed successfully"
            ),
        }

>>>>>>> dbc1faef7abfbbd7ad65a47025adad93c621d131
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception(
            "Failed to delete WireGuard client %s: %s",
            client_id,
            exc,
        )

        raise HTTPException(
            status_code=500,
<<<<<<< HEAD
            detail="Failed to delete client",
        ) from exc
=======
            detail="Failed to delete WireGuard client",
        ) from exc
>>>>>>> dbc1faef7abfbbd7ad65a47025adad93c621d131
