import psutil, time
from typing import Optional
from utils import setup_logging

log = setup_logging(__name__)


def extract_raddr(r):
    """Return (ip, port) or None for unsupported raddr shapes."""
    if r is None:
        return None
    if isinstance(r, tuple):
        if len(r) < 2:
            return None
        return r[0], r[1]
    ip = getattr(r, "ip", None)
    port = getattr(r, "port", None)
    if ip is not None and port is not None:
        return ip, port
    if hasattr(r, "__iter__") and not isinstance(r, (str, bytes)):
        try:
            it = tuple(r)
            if len(it) < 2:
                return None
            return it[0], it[1]
        except Exception:
            return None
    return None


def basic_ids(max_checks: Optional[int] = None, interval: float = 2.0, sleep_between: float = 5.0, stop_event=None):
    """Basic IDS: checks CPU and prints established remote addresses.

    If stop_event is provided (threading.Event), the loop exits when set.
    Args:
        max_checks: Maximum number of checks to perform before stopping
        interval: Time interval for CPU measurement
        sleep_between: Time to sleep between checks
        stop_event: Event to signal stopping
    """
    log.info("Monitoring system for suspicious activity...")
    checks = 0
    if isinstance(max_checks, int) and max_checks > 0:
        log.info("IDS will stop after %d checks", max_checks)

    def is_stopping():
        return stop_event is not None and stop_event.is_set()

    while True:
        try:
            # Primary stop check
            if is_stopping():
                log.info("IDS stop requested.")
                break

            cpu = psutil.cpu_percent(interval=interval)
            if cpu > 80:
                log.warning("⚠️ High CPU usage detected! Possible intrusion.")
            
            connections_found = False
            active_connections = []
            for conn in psutil.net_connections():
                # Frequent stop check
                if is_stopping():
                    log.info("IDS stop requested during connection check.")
                    return
                    
                r = getattr(conn, "raddr", None)
                if conn.status == "ESTABLISHED" and r:
                    res = extract_raddr(r)
                    if res:
                        ip, port = res
                        if not ip.startswith('127.0.0.1'):  # Filter out localhost
                            active_connections.append(f"{ip}:{port}")
                            connections_found = True
            
            if active_connections:
                # Limit output to first 5 connections + count
                total = len(active_connections)
                display_connections = active_connections[:5]
                if total > 5:
                    log.info("🔍 Active connections detected (%d total): %s, and %d more...", 
                            total, ", ".join(display_connections), total - 5)
                else:
                    log.info("🔍 Active connections detected: %s", ", ".join(display_connections))

            checks += 1
            if isinstance(max_checks, int) and max_checks > 0:
                remaining = max_checks - checks
                if remaining > 0:
                    log.info("Remaining checks: %d", remaining)
                if checks >= max_checks:
                    print("\n" + "="*50)
                    log.info("IDS monitoring completed successfully.")
                    log.info("Total checks performed: %d", checks)
                    print("="*50)
                    break
                
            if not connections_found:
                log.info("No external connections found in this check.")
                
            # Pre-sleep stop check
            if is_stopping():
                log.info("IDS stop requested before sleep.")
                break
                
            # Use shorter sleep intervals and check stop event during sleep
            for _ in range(int(sleep_between)):
                if is_stopping():
                    log.info("IDS stop requested during sleep.")
                    return
                time.sleep(1)

        except KeyboardInterrupt:
            log.info("IDS interrupted by user. Returning to menu.")
            break
        except Exception as e:
            log.error("Error in IDS loop: %s", str(e))
            if is_stopping():
                return
            time.sleep(1)  # Brief pause on error before retrying

    log.info("IDS monitoring stopped.")


if __name__ == "__main__":
    basic_ids()
