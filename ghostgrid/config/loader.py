"""Configuration loader and schema definition for GhostGrid."""
import os
import yaml
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


@dataclass
class ModbusConfig:
    host: str = "0.0.0.0"
    port: int = 502
    unit_id: int = 1
    allow_broadcast: bool = False
    response_delay_ms: int = 2
    max_clients: int = 64
    max_clients_per_ip: int = 16
    idle_timeout_s: float = 1800.0


@dataclass
class DeviceConfig:
    vendor: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    serial_number: Optional[str] = None


@dataclass
class DirectorConfig:
    enabled: bool = True
    provider: str = "mock"  # ollama, openai, mock
    model: str = "qwen2.5:1.5b"
    endpoint: str = "http://localhost:11434"
    interval_seconds: int = 60
    hardened_prompts: bool = True


@dataclass
class SimulationConfig:
    tick_interval_seconds: float = 1.0
    noise_amplitude: float = 0.02
    auto_recovery: bool = False


@dataclass
class LoggingConfig:
    db_path: str = "ghostgrid_soc.db"
    log_level: str = "INFO"
    alert_threshold_writes: int = 1
    alert_threshold_scans: int = 10
    honeytoken_registers: List[int] = field(default_factory=lambda: [40099, 40100, 40101])
    # Forwarding alerts to the SOC's SIEM (empty = off)
    alerts_jsonl_path: str = ""
    syslog_host: str = ""
    syslog_port: int = 514
    syslog_format: str = "json"
    decoy_name: str = ""


@dataclass
class GhostGridConfig:
    site_name: Optional[str] = None
    facility_type: Optional[str] = None
    sector: str = "water"
    country: str = "ZA"
    region: str = "Gauteng"
    location_code: Optional[str] = None
    security_zone: str = "OT-PMR-L2"
    modbus: ModbusConfig = field(default_factory=ModbusConfig)
    device: DeviceConfig = field(default_factory=DeviceConfig)
    director: DirectorConfig = field(default_factory=DirectorConfig)
    simulation: SimulationConfig = field(default_factory=SimulationConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    raw_data: Dict[str, Any] = field(default_factory=dict)


def load_config(config_path: Optional[str] = None) -> GhostGridConfig:
    """Load configuration from a YAML file, environment variables, or fall back to defaults."""
    data: Dict[str, Any] = {}

    candidates = []
    if config_path:
        candidates.append(config_path)
    env_cfg = os.environ.get("GHOSTGRID_CONFIG")
    if env_cfg:
        candidates.append(env_cfg)
    candidates.extend([
        os.path.join(os.path.dirname(__file__), "site.yaml"),
        os.path.join(os.path.dirname(__file__), "site.example.yaml"),
    ])

    for candidate in candidates:
        if os.path.exists(candidate):
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                break
            except Exception as e:
                print(f"[GhostGrid Config] Warning: Failed to load {candidate}: {e}")

    site_sec = data.get("site", {}) or {}
    net_sec = data.get("network", {}).get("modbus", {}) or {}
    dev_sec = data.get("device", {}) or {}
    dir_sec = data.get("director", {}) or {}
    sim_sec = data.get("simulation", {}) or {}
    log_sec = data.get("logging", {}) or {}
    siem_sec = log_sec.get("siem", {}) or {}

    ft_sector = str(site_sec.get("sector") or "water").lower()

    cfg = GhostGridConfig(
        site_name=site_sec.get("name") or None,
        facility_type=site_sec.get("facility_type") or None,
        sector=ft_sector,
        country=site_sec.get("country", "ZA"),
        region=site_sec.get("region", "Gauteng"),
        location_code=site_sec.get("location_code") or None,
        security_zone=site_sec.get("security_zone", "OT-PMR-L2"),
        modbus=ModbusConfig(
            host=os.environ.get("MODBUS_HOST", net_sec.get("host", "0.0.0.0")),
            port=int(os.environ.get("MODBUS_PORT", net_sec.get("port", 502))),
            unit_id=int(os.environ.get("MODBUS_UNIT_ID", net_sec.get("unit_id", 1))),
            allow_broadcast=bool(net_sec.get("allow_broadcast", False)),
            response_delay_ms=int(net_sec.get("response_delay_ms", 2)),
            max_clients=int(net_sec.get("max_clients", 64)),
            max_clients_per_ip=int(net_sec.get("max_clients_per_ip", 16)),
            idle_timeout_s=float(net_sec.get("idle_timeout_s", 1800.0)),
        ),
        device=DeviceConfig(
            vendor=dev_sec.get("vendor") or None,
            model=dev_sec.get("model") or None,
            firmware_version=dev_sec.get("firmware_version") or None,
            serial_number=dev_sec.get("serial_number") or None,
        ),
        director=DirectorConfig(
            enabled=bool(dir_sec.get("enabled", True)),
            provider=os.environ.get("DIRECTOR_PROVIDER", dir_sec.get("provider", "mock")),
            model=os.environ.get("DIRECTOR_MODEL", dir_sec.get("model", "qwen2.5:1.5b")),
            endpoint=os.environ.get("DIRECTOR_ENDPOINT", dir_sec.get("endpoint", "http://localhost:11434")),
            interval_seconds=int(dir_sec.get("interval_seconds", 60)),
            hardened_prompts=bool(dir_sec.get("hardened_prompts", True)),
        ),
        simulation=SimulationConfig(
            tick_interval_seconds=float(sim_sec.get("tick_interval_seconds", 1.0)),
            noise_amplitude=float(sim_sec.get("noise_amplitude", 0.02)),
            auto_recovery=bool(sim_sec.get("auto_recovery", False)),
        ),
        logging=LoggingConfig(
            db_path=os.environ.get("GHOSTGRID_DB_PATH", log_sec.get("db_path", "ghostgrid_soc.db")),
            log_level=os.environ.get("GHOSTGRID_LOG_LEVEL", log_sec.get("log_level", "INFO")),
            alert_threshold_writes=int(log_sec.get("alert_threshold_writes", 1)),
            alert_threshold_scans=int(log_sec.get("alert_threshold_scans", 10)),
            honeytoken_registers=list(log_sec.get("honeytoken_registers", [40099, 40100, 40101])),
            alerts_jsonl_path=os.environ.get("GHOSTGRID_ALERTS_JSONL", siem_sec.get("jsonl_path") or ""),
            syslog_host=os.environ.get("GHOSTGRID_SYSLOG_HOST", siem_sec.get("syslog_host") or ""),
            syslog_port=int(os.environ.get("GHOSTGRID_SYSLOG_PORT", siem_sec.get("syslog_port", 514))),
            syslog_format=os.environ.get("GHOSTGRID_SYSLOG_FORMAT", siem_sec.get("syslog_format") or "json").lower(),
            decoy_name=os.environ.get("GHOSTGRID_DECOY_NAME", siem_sec.get("decoy_name") or ""),
        ),
        raw_data=data,
    )
    return cfg
