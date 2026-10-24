from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "sqlite:///./networkhelper.db"
    data_dir: str = "./data"  # GeoIP-Datenbanken und andere Dateien
    secret_key: str = "dev-secret-change-me"
    public_url: str = "http://localhost:8080"
    allow_registration: bool = False  # nur das erste Konto und Eingeladene
    trusted_proxies: int = 1  # Proxys vor dem Webserver (Nginx Proxy Manager = 1)
    token_expire_days: int = 7
    updater_url: str = ""  # leer = kein Update-Dienst
    timezone: str = "Europe/Berlin"
    router_type: str = "fritzbox"  # fritzbox | other: passende Anleitungen zum Schließen von Ports
    background_jobs: bool = True  # Tests schalten die Hintergrundaufgaben ab

    # E-Mail-Warnungen
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_starttls: bool = True
    alert_min_severity: str = "warn"  # info | warn | crit

    # Porkbun (DNS)
    porkbun_api_key: str = ""
    porkbun_secret_key: str = ""
    porkbun_domains: str = ""  # leer = alle Domains des Kontos mit API-Zugriff
    porkbun_api_url: str = "https://api.porkbun.com/api/json/v3"
    dyndns_enabled: bool = True
    dyndns_interval_min: int = 5
    dns_new_record_type: str = "A"  # A (öffentliche IP, per DynDNS gepflegt) | CNAME (auf die Hauptdomain)
    public_ip_override: str = ""

    # Nginx Proxy Manager (Proxy Hosts lesen)
    npm_url: str = ""
    npm_email: str = ""
    npm_password: str = ""
    npm_auto_dns: bool = False
    npm_auto_monitors: bool = True

    # Sicherheit
    scan_enabled: bool = True
    scan_interval_h: int = 6
    scan_ports: str = ""  # leer = eingebaute Liste häufiger Ports
    scan_targets: str = ""  # zusätzliche Ziele (Hostnamen oder IPs), die öffentliche IP ist immer dabei
    expected_ports: str = "80,443"
    shodan_enabled: bool = True
    detect_enabled: bool = True
    auto_block: bool = False
    auto_block_hours: int = 24
    site_check_interval_h: int = 6
    monitor_interval_s: int = 60
    retention_days: int = 30
    geoip_enabled: bool = True
    geoip_city: bool = True
    two_factor_required: bool = False  # alle Konten müssen die Zwei-Faktor-Anmeldung einrichten
    exposure_enabled: bool = True  # Selbsttest: sind .env, .git usw. auf den eigenen Seiten lesbar?
    exposure_interval_h: int = 24  # Städtedatenbank für die Karte (rund 130 MB)

    class Config:
        env_file = ".env"


settings = Settings()
