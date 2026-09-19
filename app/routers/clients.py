import os

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import WireGuardClient
from app.schemas import (
    ClientConfigResponse,
    ClientCreateRequest,
    ClientResponse,
)
from app.services.client_service import ClientService
from app.services.wireguard import WireGuardService


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
        result = service.create_client(payload.name)

        client = result["client"]
        private_key = result["private_key"]

        wireguard = WireGuardService()

        # Read the server public key from the environment.
        server_public_key = os.getenv(
            "WIREGUARD_SERVER_PUBLIC_KEY"
        )

        if not server_public_key:
            raise RuntimeError(
                "WIREGUARD_SERVER_PUBLIC_KEY is not configured"
            )

        client_config = wireguard.generate_client_config(
            client_private_key=private_key,
            server_public_key=server_public_key,
            client_ip=client.vpn_ip,
            full_tunnel=True,
        )

        return {
            "name": client.name,
            "vpn_ip": client.vpn_ip,
            "config": client_config,
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Failed to create WireGuard client",
        ) from exc


@router.get(
    "",
    response_model=list[ClientResponse],
)
def list_clients(
    db: Session = Depends(get_db),
):
    return db.scalars(
        select(WireGuardClient).order_by(
            WireGuardClient.id.desc()
        )
    ).all()


@router.delete(
    "/{client_id}",
)
def delete_client(
    client_id: int,
    db: Session = Depends(get_db),
):
    service = ClientService(db)

    try:
        service.delete_client(client_id)

        return {
            "message": "WireGuard client removed successfully",
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Failed to delete WireGuard client",
        ) from exc