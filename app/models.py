from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class WireGuardClient(Base):
    __tablename__ = "wireguard_clients"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(100),
        unique=True,
        nullable=False,
    )

    public_key: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        nullable=False,
    )

    vpn_ip: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        nullable=False,
    )

    vless_uuid: Mapped[str | None] = mapped_column(
        String(36),
        unique=True,
        nullable=True,
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )