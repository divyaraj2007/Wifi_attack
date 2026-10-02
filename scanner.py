import os
import glob
import tempfile

from rich.prompt import Prompt
from rich.table import Table

from richtools import run_command_with_privilege


def classify_security(privacy, cipher, auth):
    """
    Classify a network from its airodump-ng Privacy / Cipher / Authentication
    fields.

    Returns a tuple: (label, color, crackable_with_this_tool, note)

    This is informational. The point of distinguishing WPA3 is that the
    WPA2-style "capture handshake -> offline dictionary crack" flow does NOT
    work against WPA3-SAE, so the tool should say so instead of wasting the
    user's time.
    """
    privacy = (privacy or "").upper()
    auth = (auth or "").upper()

    has_sae = "SAE" in auth
    has_psk = "PSK" in auth
    has_mgt = "MGT" in auth  # 802.1X / Enterprise

    # Open network
    if "OPN" in privacy or (privacy == "" and not auth):
        return ("Open", "bright_black", False,
                "No encryption. Nothing to crack.")

    # WEP (legacy)
    if "WEP" in privacy:
        return ("WEP", "red", True,
                "Legacy/broken. Different attack than WPA (not this handshake flow).")

    # Enterprise (802.1X) - WPA2-Enterprise or WPA3-Enterprise
    if has_mgt:
        return ("Enterprise (802.1X)", "magenta", False,
                "RADIUS-backed. Not a PSK handshake; this tool's cracker does not apply.")

    # WPA3 transition mode: advertises both SAE (WPA3) and PSK (WPA2)
    if has_sae and has_psk:
        return ("WPA2/WPA3 Transition", "yellow", False,
                "SAE present. The WPA2 side exists for compatibility, but this "
                "is the configuration WPA3 is meant to phase out, not a reliable "
                "crack path. Offline SAE cracking is not supported here.")

    # Pure WPA3-SAE
    if has_sae or "WPA3" in privacy:
        return ("WPA3-SAE (Personal)", "green", False,
                "SAE handshake. No offline-crackable 4-way handshake; PMF is "
                "mandatory so deauth is also blocked. Not attackable with this tool.")

    # WPA2-PSK
    if "WPA2" in privacy and has_psk:
        return ("WPA2-PSK", "cyan", True,
                "Classic 4-way handshake. Capture + dictionary crack applies.")

    # WPA(1)-PSK
    if "WPA" in privacy and has_psk:
        return ("WPA-PSK", "cyan", True,
                "Legacy WPA. Capture + dictionary crack applies.")

    # Fallback
    label = privacy if privacy else "Unknown"
    return (label, "white", False, "Could not classify; inspect manually.")


def _parse_airodump_csv(path):
    """Parse the AP section of an airodump-ng CSV dump into a list of dicts."""
    networks = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return networks

    for line in lines:
        # The AP section ends at the blank line before the "Station MAC" section.
        if line.strip().startswith("Station MAC"):
            break
        if not line.strip():
            continue
        # Skip the header row.
        if line.strip().startswith("BSSID"):
            continue

        cols = [c.strip() for c in line.split(",")]
        if len(cols) < 14:
            continue

        networks.append({
            "bssid": cols[0],
            "channel": cols[3],
            "privacy": cols[5],
            "cipher": cols[6],
            "auth": cols[7],
            "power": cols[8],
            "essid": cols[13],
        })
    return networks


def scan_and_classify(console):
    """
    Run a timed scan, then print a table that labels each network's security
    and whether this tool's handshake-capture/crack flow can actually work on it.
    """
    console.print("[bold green]WPA3-aware scan[/bold green]")
    duration = Prompt.ask("Scan duration in seconds", default="15")
    try:
        int(duration)
    except ValueError:
        duration = "15"

    tmp_dir = tempfile.mkdtemp(prefix="wifiscan_")
    prefix = os.path.join(tmp_dir, "scan")

    console.print(f"[bold yellow]Scanning for {duration}s... (please wait)[/bold yellow]")
    run_command_with_privilege("airmon-ng start wlan0")
    # timeout stops airodump cleanly after the chosen window.
    run_command_with_privilege(
        f"timeout {duration} airodump-ng --output-format csv -w {prefix} wlan0mon"
    )
    run_command_with_privilege("airmon-ng stop wlan0mon")

    csv_files = sorted(glob.glob(prefix + "-*.csv"))
    if not csv_files:
        console.print("[bold red]No scan output produced. Is wlan0 a valid "
                      "monitor-capable interface?[/bold red]")
        return

    networks = _parse_airodump_csv(csv_files[-1])
    if not networks:
        console.print("[bold yellow]No networks found.[/bold yellow]")
        return

    table = Table(title="Networks (WPA3-aware)")
    table.add_column("ESSID", style="bold")
    table.add_column("BSSID")
    table.add_column("Ch", justify="right")
    table.add_column("Pwr", justify="right")
    table.add_column("Security")
    table.add_column("This tool?", justify="center")

    # Sort by signal power (closest/strongest first).
    def _pwr(n):
        try:
            return int(n["power"])
        except ValueError:
            return -999
    networks.sort(key=_pwr, reverse=True)

    for n in networks:
        label, color, crackable, _note = classify_security(
            n["privacy"], n["cipher"], n["auth"]
        )
        verdict = "[green]yes[/green]" if crackable else "[red]no[/red]"
        essid = n["essid"] if n["essid"] else "[dim]<hidden>[/dim]"
        table.add_row(
            essid,
            n["bssid"],
            n["channel"],
            n["power"],
            f"[{color}]{label}[/{color}]",
            verdict,
        )

    console.print(table)
    console.print(
        "\n[dim]'This tool? = no' means WPA3-SAE / Enterprise / Open — the "
        "capture+crack flow does not apply. See option 6 (Defense Tips) for "
        "the WPA3 explanation.[/dim]"
    )


def scan_networks(console):
    """Interactive live scan (original airodump-ng view)."""
    console.print("[bold green]Scanning for networks... (Press CTRL+C to stop)[/bold green]")
    console.print("[dim]Tip: the 'AUTH' column shows SAE for WPA3 and PSK for WPA2.[/dim]")
    try:
        run_command_with_privilege("airmon-ng start wlan0")
        run_command_with_privilege("airodump-ng wlan0mon")
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Stopping scan...[/bold yellow]")
        run_command_with_privilege("airmon-ng stop wlan0mon")
