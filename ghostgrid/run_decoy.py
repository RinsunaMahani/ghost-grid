"""Main entrypoint to run the GhostGrid OT Decoy."""
import argparse
import asyncio
import logging
import os
import signal
import sys
import time

# Reconfigure standard streams to UTF-8 with replacement for Windows file redirection
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# Ensure repository root is on sys.path
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.dirname(current_dir)
for p in (parent_dir, current_dir):
    if p not in sys.path:
        sys.path.insert(0, p)

from ghostgrid.config import load_config
from ghostgrid.core.identity import generate_site_identity, save_identity, load_identity
from ghostgrid.core.logger import EventLogger
from ghostgrid.profiles import create_profile
from ghostgrid.core.state import StateEngine
from ghostgrid.core.director.llm_client import LLMClient
from ghostgrid.core.director import ScenarioDirector
from ghostgrid.core.protocol import ModbusServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ghostgrid.main")


def _safe_print(text: str = ""):
    """Print safely to stdout even if redirected to a limited-encoding file on Windows."""
    try:
        print(text)
    except UnicodeEncodeError:
        encoding = getattr(sys.stdout, "encoding", None) or "ascii"
        print(text.encode(encoding, errors="replace").decode(encoding))


def print_banner(cfg, identity):
    # Standard ASCII banner that renders identically across UTF-8, Windows cp1252, and ASCII log sinks
    _safe_print("\n" + "=" * 65)
    _safe_print(r"""
   ____ _               _    ____      _     _ 
  / ___| |__   ___  ___| |_ / ___|_ __(_) __| |
 | |  _| '_ \ / _ \/ __| __| |  _| '__| |/ _` |
 | |_| | | | | (_) \__ \ |_| |_| | |  | | (_| |
  \____|_| |_|\___/|___/\__|\____|_|  |_|\__,_|
    """)
    _safe_print("      Air-Gapped Deception for Critical Infrastructure")
    _safe_print("=" * 65)
    _safe_print(f" Site Name:        {identity.site_name}")
    _safe_print(f" Sector:           {identity.sector.upper()} ({identity.facility_type})")
    _safe_print(f" Emulated Device:  {identity.vendor} - {identity.model} ({identity.firmware_version})")
    _safe_print(f" Serial Number:    {identity.serial_number} | MAC: {identity.mac_address}")
    _safe_print(f" Modbus TCP Port:  {cfg.modbus.host}:{cfg.modbus.port} (Unit ID: {cfg.modbus.unit_id})")
    _safe_print(f" Active Tags:      {len(identity.tags)} mapped tags")
    ht_count = sum(1 for t in identity.tags.values() if t.is_honeytoken)
    _safe_print(f" Honeytokens:      {ht_count} traps armed")
    _safe_print(f" Security Zone:    {identity.security_zone} | Code: {identity.location_code}")
    _safe_print(f" Event Database:   {cfg.logging.db_path}")
    _safe_print(f" AI Director:      {'Enabled (' + cfg.director.provider + ')' if cfg.director.enabled else 'Disabled'}")
    _safe_print("=" * 65 + "\n")


async def main():
    parser = argparse.ArgumentParser(description="GhostGrid OT Honeypot & Deception Platform")
    parser.add_argument("--config", "-c", type=str, help="Path to site.yaml config file")
    parser.add_argument("--sector", "-s", type=str, choices=["water", "power"], help="Override sector profile")
    parser.add_argument("--port", "-p", type=int, help="Override Modbus listening port")
    args = parser.parse_args()

    cfg = load_config(args.config)
    if args.sector:
        cfg.sector = args.sector
    if args.port:
        cfg.modbus.port = args.port

    # Set configured log level
    log_lvl = getattr(logging, cfg.logging.log_level.upper(), logging.INFO)
    logging.getLogger().setLevel(log_lvl)

    # 1. Site Identity Persistence: load saved identity if sector matches, else generate & save
    id_file = os.environ.get("GHOSTGRID_IDENTITY_PATH", "ghostgrid_identity.json")
    identity = load_identity(id_file)
    if not identity or identity.sector != cfg.sector:
        identity = generate_site_identity(
            sector=cfg.sector,
            site_name=cfg.site_name,
            vendor=cfg.device.vendor,
            model=cfg.device.model,
            firmware_version=cfg.device.firmware_version,
            serial_number=cfg.device.serial_number,
            unit_id=cfg.modbus.unit_id,
            location_code=cfg.location_code,
            security_zone=cfg.security_zone,
        )
        save_identity(identity, id_file)

    print_banner(cfg, identity)

    # 2. Initialize Event Logger (SQLite with background batch queue and stale session cleanup on decoy start)
    event_logger = EventLogger(
        db_path=cfg.logging.db_path,
        alert_threshold_writes=cfg.logging.alert_threshold_writes,
        alert_threshold_scans=cfg.logging.alert_threshold_scans,
        honeytoken_registers=cfg.logging.honeytoken_registers,
        cleanup_stale_sessions=True,
    )

    # 3. Create Sector Physics Profile
    profile = create_profile(
        sector=cfg.sector,
        identity=identity,
        noise_amplitude=cfg.simulation.noise_amplitude,
    )

    # 4. Initialize Process State Engine
    state_file = os.environ.get("GHOSTGRID_STATE_PATH", "ghostgrid_state.json")
    state_engine = StateEngine(
        identity=identity,
        profile=profile,
        tick_interval=cfg.simulation.tick_interval_seconds,
        auto_recovery=cfg.simulation.auto_recovery,
        state_file_path=state_file,
    )
    state_engine.start()

    # 5. Initialize Scenario Director (Local AI model / Offline generator)
    llm_client = LLMClient(
        provider=cfg.director.provider,
        model=cfg.director.model,
        endpoint=cfg.director.endpoint,
        hardened=cfg.director.hardened_prompts,
    )
    director = ScenarioDirector(
        identity=identity,
        state_engine=state_engine,
        event_logger=event_logger,
        llm_client=llm_client,
        interval_seconds=cfg.director.interval_seconds,
        enabled=cfg.director.enabled,
    )
    director.start()

    # 6. Initialize Modbus TCP Server
    modbus_server = ModbusServer(
        host=cfg.modbus.host,
        port=cfg.modbus.port,
        unit_id=cfg.modbus.unit_id,
        state_engine=state_engine,
        identity=identity,
        event_logger=event_logger,
        response_delay_ms=cfg.modbus.response_delay_ms,
        allow_broadcast=cfg.modbus.allow_broadcast,
    )

    stop_event = asyncio.Event()

    def handle_stop():
        logger.info("Received termination signal. Shutting down GhostGrid gracefully...")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, handle_stop)
        except (NotImplementedError, RuntimeError):
            pass

    try:
        await modbus_server.start()
        logger.info("GhostGrid decoy active. Awaiting adversary reconnaissance...")
        while not stop_event.is_set():
            await asyncio.sleep(0.5)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.error("Fatal error running GhostGrid: %s", e, exc_info=True)
    finally:
        await modbus_server.stop()
        director.stop()
        state_engine.stop()
        event_logger.close()
        logger.info("GhostGrid cleanly stopped.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
