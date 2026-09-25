from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ClientCreateRequest(BaseModel):
    name: str
    mode: str = "wireguard"


class ClientResponse(BaseModel):
    id: int
    name: str
    public_key: str | None
    vpn_ip: str
    is_active: bool
    created_at: datetime
    vless_uuid: str | None = None

    model_config = ConfigDict(from_attributes=True)


class VlessConfig(BaseModel):
    uuid: str
    address: str
    port: int
    network: str = "ws"
    path: str
    security: str = "tls"
    sni: str


class ClientConfigResponse(BaseModel):
    name: str
    vpn_ip: str
    config: str | None = None
    vless: VlessConfig | None = None