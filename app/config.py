from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "WireGuard Manager"
    database_url: str = "sqlite:///./data/wireguard.db"

    # ---------- WireGuard ----------
    wireguard_interface: str = "wg0"
    wireguard_config_path: str = "/etc/wireguard/wg0.conf"
    wireguard_server_public_ip: str = "2.25.222.27"
    wireguard_server_port: int = 443
    wireguard_server_vpn_ip: str = "10.104.5.1"
    wireguard_network: str = "10.104.5.0/24"
    wireguard_dns: str = "1.1.1.1, 1.0.0.1"
    wireguard_mtu: int = 1280

    wireguard_server_public_key: str

    # ---------- Xray / VLESS ----------
    vless_enabled: bool = True
    vless_address: str = "2.25.222.27"
    vless_port: int = 443
    vless_path: str = "/vless-ws"
    vless_network: str = "ws"
    vless_security: str = "tls"
    vless_sni: str = "2.25.222.27"
    xray_config_path: str = "/usr/local/etc/xray/config.json"

    # Load the WireGuard server public key from .env.
    wireguard_server_public_key: str

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
