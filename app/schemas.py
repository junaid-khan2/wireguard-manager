from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ClientCreateRequest(BaseModel):
    name: str


class ClientResponse(BaseModel):
    id: int
    name: str
    public_key: str
    vpn_ip: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ClientConfigResponse(BaseModel):
    name: str
    vpn_ip: str
    config: str