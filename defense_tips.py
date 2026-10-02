from rich.panel import Panel

def display_defense_tips(console):
    tips = """
    [bold green]1. Use WPA3 encryption whenever possible.[/bold green]
    [white]WPA3 replaces the WPA2 4-way handshake with SAE (Simultaneous
    Authentication of Equals, the "Dragonfly" handshake). SAE is resistant to
    offline dictionary attacks: there is no captured handshake an attacker can
    feed into aircrack-ng/hashcat and grind against a wordlist. Even a weak
    password cannot be brute-forced offline the way WPA2 passwords can.[/white]

    [bold green]2. Prefer WPA3-only over WPA2/WPA3 "transition" mode.[/bold green]
    [white]Transition mode advertises both WPA3 (SAE) and WPA2 (PSK) so old
    devices can still connect. That WPA2 fallback re-introduces the crackable
    handshake and enables downgrade attacks. If every client supports WPA3,
    disable the mixed mode and run WPA3-only.[/white]

    [bold green]3. Keep 802.11w (Management Frame Protection) required.[/bold green]
    [white]PMF is mandatory under WPA3 and encrypts/authenticates management
    frames, which neutralises deauthentication attacks. On WPA2 networks, set
    PMF to "required" (not just "optional") where your devices support it.[/white]

    [bold green]4. Use a long, random Wi-Fi password.[/bold green]
    [white]WPA3 makes offline cracking impractical, but online guessing and
    shoulder-surfing still exist. Use a long passphrase (a random 4-5 word
    phrase or 16+ mixed characters) and avoid common words.[/white]

    [bold green]5. Disable WPS (Wi-Fi Protected Setup).[/bold green]
    [white]WPS PIN has known brute-force vulnerabilities that bypass your
    passphrase strength entirely. Turn it off.[/white]

    [bold green]6. Keep router firmware updated.[/bold green]
    [white]Early WPA3 implementations had side-channel bugs (the "Dragonblood"
    class). Vendors patched these; staying on current firmware closes them and
    other issues.[/white]

    [bold green]7. Regularly monitor your Wi-Fi for unknown devices.[/bold green]
    [white]Check your router's admin panel for unfamiliar MAC addresses, and
    watch for rogue/"evil twin" APs broadcasting your SSID.[/white]
    """
    console.print(Panel(tips, title="[bold cyan]Wi-Fi Defense Tips[/bold cyan]", border_style="cyan"))

