#!/usr/bin/env python3
"""
Wireless Intrusion Detection System (WIDS)
Comprehensive wireless attack detection with all advanced features

Features:
- Mass deauthentication/disassociation attack detection
- WEP attack detection (chopchop, fragmentation, broadcast data)
- WPA/WPA2 attack detection (handshake capture, downgrade attacks)
- WPS brute force detection (EAP flooding)
- Rogue AP and Evil Twin detection
- Beacon flooding detection
- Authentication/Association DoS detection
- MAC spoofing and vendor analysis
- TKIP Michael shutdown exploitation detection
- Client probing and SSID tracking
- Comprehensive logging (JSON + SQLite + text)
"""

import os
import platform
import sys
import json
import time
import sqlite3
import argparse
import signal
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, Optional, Set, List, Tuple
import subprocess

# Scapy imports
try:
    from scapy.all import (
        sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, Dot11Disas,
        Dot11ProbeReq, Dot11ProbeResp, Dot11AssoReq, Dot11AssoResp,
        Dot11Auth, Dot11ReassoReq, EAPOL, Dot11QoS, RadioTap
    )
except ImportError:
    print("Error: Scapy not found. Install with: pip3 install scapy")
    sys.exit(1)

import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('WIDS')

# ============================================================================
# DETECTION THRESHOLDS - Configurable
# ============================================================================

# Deauthentication attack thresholds
DEAUTH_THRESHOLD = 10          # Deauth frames in window
DEAUTH_WINDOW = 5              # seconds

# Disassociation attack thresholds
DISASSOC_THRESHOLD = 10        # Disassoc frames in window
DISASSOC_WINDOW = 5            # seconds

# WPA Downgrade (deauth + disassoc together)
WPA_DOWNGRADE_THRESHOLD = 10   # Combined frames

# Probe request abuse
PROBE_THRESHOLD = 50           # Probe requests in window
PROBE_WINDOW = 60              # seconds

# Beacon flooding
BEACON_RATE_THRESHOLD = 30     # Beacons per second (normal is ~20)
BEACON_FLOOD_THRESHOLD = 15
# Different SSIDs from same MAC

# Authentication DoS
AUTH_THRESHOLD = 80            # Auth frames
AUTH_WINDOW = 10               # seconds

# Association flooding
ASSOC_THRESHOLD = 8            # Association requests
ASSOC_WINDOW = 10              # seconds

# WEP attack detection
WEP_BROADCAST_DATA = 50        # Broadcast data packets
WEP_DATA_WINDOW = 30           # seconds
CHOPCHOP_THRESHOLD = 5         # Chopchop packets
FRAGMENTATION_THRESHOLD = 5    # Fragmentation packets

# WPS brute force
WPS_EAP_THRESHOLD = 2          # EAP exchanges
WPS_EAP_WINDOW = 60            # seconds

# TKIP Michael shutdown
TKIP_MICHAEL_THRESHOLD = 5     # Michael MIC failure packets

# QoS data threshold for TKIPTUN
QOS_DATA_THRESHOLD = 1         # QoS data packets (suspicious pattern)

# ============================================================================
# DATABASE MANAGEMENT
# ============================================================================

class WIDSDatabase:
    """SQLite database for comprehensive WIDS alerts"""
    
    def __init__(self, db_path: str = '/opt/wids/wids_alerts.db'):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._create_tables()
    
    def _create_tables(self):
        """Create comprehensive database tables"""
        cursor = self.conn.cursor()
        
        # Main alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS wireless_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                src_mac TEXT,
                dst_mac TEXT,
                bssid TEXT,
                ssid TEXT,
                channel INTEGER,
                signal_strength INTEGER,
                frame_count INTEGER,
                details TEXT,
                attack_signature TEXT,
                raw_json TEXT,
                logged_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Network topology table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS known_aps (
                bssid TEXT PRIMARY KEY,
                ssid TEXT,
                channel INTEGER,
                encryption TEXT,
                first_seen TEXT,
                last_seen TEXT,
                beacon_count INTEGER DEFAULT 0
            )
        ''')
        
        # Client associations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS client_associations (
                client_mac TEXT,
                bssid TEXT,
                ssid TEXT,
                first_seen TEXT,
                last_seen TEXT,
                PRIMARY KEY (client_mac, bssid)
            )
        ''')
        
        # Probing devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS probing_devices (
                client_mac TEXT,
                probed_ssid TEXT,
                probe_count INTEGER DEFAULT 1,
                first_seen TEXT,
                last_seen TEXT,
                PRIMARY KEY (client_mac, probed_ssid)
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON wireless_alerts(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attack_type ON wireless_alerts(attack_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON wireless_alerts(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_src_mac ON wireless_alerts(src_mac)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_bssid ON wireless_alerts(bssid)')
        
        self.conn.commit()
    
    def insert_alert(self, alert_data: Dict):
        """Insert alert into database"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO wireless_alerts (
                timestamp, attack_type, severity, src_mac, dst_mac, 
                bssid, ssid, channel, signal_strength, frame_count, 
                details, attack_signature, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert_data.get('timestamp'),
            alert_data.get('attack_type'),
            alert_data.get('severity'),
            alert_data.get('src_mac'),
            alert_data.get('dst_mac'),
            alert_data.get('bssid'),
            alert_data.get('ssid'),
            alert_data.get('channel'),
            alert_data.get('signal_strength'),
            alert_data.get('frame_count'),
            alert_data.get('details'),
            alert_data.get('attack_signature'),
            json.dumps(alert_data)
        ))
        self.conn.commit()
    
    def update_ap(self, bssid: str, ssid: str, channel: int, encryption: str = None):
        """Update or insert AP information"""
        cursor = self.conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute('''
            INSERT INTO known_aps (bssid, ssid, channel, encryption, first_seen, last_seen, beacon_count)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(bssid) DO UPDATE SET
                last_seen = ?,
                beacon_count = beacon_count + 1,
                ssid = CASE WHEN ssid != ? THEN ? ELSE ssid END
        ''', (bssid, ssid, channel, encryption, now, now, now, ssid, ssid))
        self.conn.commit()
    
    def update_client_association(self, client_mac: str, bssid: str, ssid: str):
        """Update client association"""
        cursor = self.conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute('''
            INSERT INTO client_associations (client_mac, bssid, ssid, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(client_mac, bssid) DO UPDATE SET
                last_seen = ?
        ''', (client_mac, bssid, ssid, now, now, now))
        self.conn.commit()
    
    def update_probing_device(self, client_mac: str, ssid: str):
        """Update probing device information"""
        cursor = self.conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute('''
            INSERT INTO probing_devices (client_mac, probed_ssid, probe_count, first_seen, last_seen)
            VALUES (?, ?, 1, ?, ?)
            ON CONFLICT(client_mac, probed_ssid) DO UPDATE SET
                probe_count = probe_count + 1,
                last_seen = ?
        ''', (client_mac, ssid, now, now, now))
        self.conn.commit()
    
    def get_client_previous_bssid(self, client_mac: str) -> Optional[Tuple[str, str]]:
        """Get previous BSSID for a client"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT bssid, ssid FROM client_associations
            WHERE client_mac = ?
            ORDER BY last_seen DESC
            LIMIT 1
        ''', (client_mac,))
        result = cursor.fetchone()
        return result if result else None
    
    def close(self):
        """Close database connection"""
        self.conn.close()

# ============================================================================
# MAC OUI DATABASE (Vendor Lookup)
# ============================================================================

class MACVendorDB:
    """MAC OUI vendor database"""
    
    def __init__(self):
        self.oui_db = {}
        self._load_oui_db()
    
    def _load_oui_db(self):
        """Load OUI database from file if available"""
        oui_file = '/opt/wids/mac-oui.db'
        if os.path.exists(oui_file):
            try:
                with open(oui_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and ' ' in line:
                            oui, vendor = line.split(' ', 1)
                            self.oui_db[oui.upper()] = vendor
                logger.info(f"Loaded {len(self.oui_db)} OUI entries")
            except Exception as e:
                logger.warning(f"Could not load OUI database: {e}")
    
    def lookup(self, mac: str) -> Optional[str]:
        """Lookup vendor for MAC address"""
        if not mac or len(mac) < 8:
            return None
        oui = mac[:8].upper().replace(':', '')
        return self.oui_db.get(oui)

# ============================================================================
# MAIN WIDS DETECTOR CLASS
# ============================================================================

class WIDSDetector:
    """Wireless Intrusion Detection System"""
    
    def __init__(self, interface: str, log_dir: str = '/opt/wids', 
                 enable_text_log: bool = True, hide_probes: bool = False):
        self.interface = interface
        self.log_dir = log_dir
        self.enable_text_log = enable_text_log
        self.hide_probes = hide_probes
        os.makedirs(log_dir, exist_ok=True)
        
        # Initialize database
        self.db = WIDSDatabase(os.path.join(log_dir, 'wids_alerts.db'))
        
        # Initialize MAC vendor database
        self.mac_vendor = MACVendorDB()
        
        # Text log file
        if self.enable_text_log:
            self.text_log_file = os.path.join(log_dir, 'wids_events.log')
            self._write_text_log("\n" + "="*80)
            self._write_text_log(f"WIDS Session Started: {datetime.now()}")
            self._write_text_log("="*80 + "\n")
        
        # ====================================================================
        # Detection state tracking with time windows
        # ====================================================================
        self.deauth_counters = defaultdict(lambda: deque())
        self.disassoc_counters = defaultdict(lambda: deque())
        self.probe_counters = defaultdict(lambda: deque())
        self.beacon_counters = defaultdict(lambda: deque())
        self.auth_counters = defaultdict(lambda: deque())
        self.assoc_counters = defaultdict(lambda: deque())
        self.wep_data_counters = defaultdict(lambda: deque())
        self.eap_counters = defaultdict(lambda: deque())
        self.chopchop_counters = defaultdict(lambda: deque())
        self.fragmentation_counters = defaultdict(lambda: deque())
        self.tkip_michael_counters = defaultdict(lambda: deque())
        self.qos_data_counters = defaultdict(lambda: deque())
        
        # Network topology tracking
        self.known_aps: Dict[str, Dict] = {}
        self.ssid_to_bssids: Dict[str, Set[str]] = defaultdict(set)
        self.client_associations: Dict[str, str] = {}
        self.mac_vendors: Dict[str, Set[str]] = defaultdict(set)
        self.probing_devices: Dict[str, Set[str]] = defaultdict(set)
        
        # Alert suppression (avoid duplicate alerts)
        self.alert_cache: Dict[str, float] = {}
        self.alert_cooldown = 30  # seconds
        
        # Statistics
        self.frame_count = 0
        self.alert_count = 0
        self.start_time = time.time()
        
        # Signature tracking for combined attacks
        self.combined_attack_signatures = defaultdict(lambda: {
            'deauth': 0,
            'disassoc': 0,
            'last_update': time.time()
        })
        
        logger.info(f"WIDS initialized on interface {interface}")
        logger.info(f"Logs directory: {log_dir}")
        logger.info(f"Text logging: {'enabled' if enable_text_log else 'disabled'}")
        logger.info(f"Hide probes: {'yes' if hide_probes else 'no'}")
    
    def _write_text_log(self, message: str):
        """Write to text log file"""
        if self.enable_text_log:
            try:
                with open(self.text_log_file, 'a') as f:
                    f.write(message + '\n')
            except Exception as e:
                logger.error(f"Failed to write text log: {e}")
    
    def _write_json_log(self, alert_data: Dict):
        """Write alert to JSON log file"""
        log_file = os.path.join(self.log_dir, 'wids_alerts.json')
        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(alert_data) + '\n')
        except Exception as e:
            logger.error(f"Failed to write JSON log: {e}")
    
    def _should_alert(self, alert_key: str) -> bool:
        """Check if alert should be suppressed (cooldown period)"""
        now = time.time()
        if alert_key in self.alert_cache:
            if now - self.alert_cache[alert_key] < self.alert_cooldown:
                return False
        self.alert_cache[alert_key] = now
        return True
    
    def _create_alert(self, attack_type: str, severity: str, 
                     src_mac: Optional[str] = None,
                     dst_mac: Optional[str] = None,
                     bssid: Optional[str] = None,
                     ssid: Optional[str] = None,
                     channel: Optional[int] = None,
                     signal_strength: Optional[int] = None,
                     frame_count: Optional[int] = None,
                     attack_signature: Optional[str] = None,
                     details: str = "") -> Dict:
        """Create comprehensive alert with vendor lookup"""
        
        # Create alert key for deduplication
        alert_key = f"{attack_type}:{src_mac}:{dst_mac}:{bssid}"
        if not self._should_alert(alert_key):
            return None
        
        # Lookup vendors for MACs
        src_vendor = self.mac_vendor.lookup(src_mac) if src_mac else None
        dst_vendor = self.mac_vendor.lookup(dst_mac) if dst_mac else None
        bssid_vendor = self.mac_vendor.lookup(bssid) if bssid else None
        
        alert = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'alert_type': 'wireless',
            'attack_type': attack_type,
            'severity': severity,
            'src_mac': src_mac,
            'src_vendor': src_vendor,
            'dst_mac': dst_mac,
            'dst_vendor': dst_vendor,
            'bssid': bssid,
            'bssid_vendor': bssid_vendor,
            'ssid': ssid,
            'channel': channel,
            'signal_strength': signal_strength,
            'frame_count': frame_count,
            'attack_signature': attack_signature,
            'details': details,
            'interface': self.interface
        }
        
        self.alert_count += 1
        
        # Format alert message
        severity_color = {
            'critical': '\033[1;91m',  # Bright red
            'high': '\033[91m',         # Red
            'medium': '\033[93m',       # Yellow
            'low': '\033[92m'           # Green
        }
        reset_color = '\033[0m'
        
        color = severity_color.get(severity, '')
        alert_msg = f"{color}[{severity.upper()}]{reset_color} {attack_type.upper()}: {details}"
        
        # Log to console
        logger.warning(alert_msg)
        
        # Add vendor info to console output
        if src_vendor:
            logger.info(f"   Source vendor: {src_vendor}")
        if dst_vendor and dst_mac != 'ff:ff:ff:ff:ff:ff':
            logger.info(f"   Destination vendor: {dst_vendor}")
        
        # Write to JSON log
        self._write_json_log(alert)
        
        # Write to text log
        if self.enable_text_log:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self._write_text_log(f"\n[{timestamp}] [{severity.upper()}] {attack_type.upper()}")
            self._write_text_log(f"  {details}")
            if src_mac:
                self._write_text_log(f"  Source MAC: {src_mac}" + (f" ({src_vendor})" if src_vendor else ""))
            if dst_mac:
                self._write_text_log(f"  Destination MAC: {dst_mac}" + (f" ({dst_vendor})" if dst_vendor else ""))
            if bssid:
                self._write_text_log(f"  BSSID: {bssid}" + (f" ({bssid_vendor})" if bssid_vendor else ""))
            if ssid:
                self._write_text_log(f"  SSID: {ssid}")
            if frame_count:
                self._write_text_log(f"  Frame count: {frame_count}")
        
        # Write to database
        self.db.insert_alert(alert)
        
        return alert
    
    def _get_signal_strength(self, pkt) -> Optional[int]:
        """Extract signal strength from packet"""
        if hasattr(pkt, 'dBm_AntSignal'):
            return pkt.dBm_AntSignal
        if pkt.haslayer(RadioTap):
            try:
                return pkt[RadioTap].dBm_AntSignal
            except:
                pass
        return None
    
    def _get_channel(self, pkt) -> Optional[int]:
        """Extract channel from packet"""
        # From RadioTap
        if pkt.haslayer(RadioTap):
            try:
                if hasattr(pkt[RadioTap], 'Channel'):
                    freq = pkt[RadioTap].Channel
                    # Convert frequency to channel
                    if 2412 <= freq <= 2484:
                        return (freq - 2407) // 5
                    elif 5180 <= freq <= 5825:
                        return (freq - 5000) // 5
            except:
                pass
        
        # From Dot11Elt (DS Parameter Set)
        if pkt.haslayer(Dot11Elt):
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 3:  # DS Parameter set
                    try:
                        return ord(elt.info)
                    except:
                        pass
                elt = elt.payload.getlayer(Dot11Elt)
        return None
    
    def _get_ssid(self, pkt) -> Optional[str]:
        """Extract SSID from packet"""
        if pkt.haslayer(Dot11Elt):
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 0:  # SSID
                    try:
                        ssid = elt.info.decode('utf-8', errors='ignore')
                        # Filter out non-printable characters
                        ssid = ''.join(c for c in ssid if c.isprintable())
                        return ssid if ssid else None
                    except:
                        return None
                elt = elt.payload.getlayer(Dot11Elt)
        return None
    
    def _get_encryption(self, pkt) -> str:
        """Determine encryption type from beacon"""
        if not pkt.haslayer(Dot11Beacon):
            return "unknown"
        
        cap = pkt[Dot11Beacon].cap
        privacy = bool(cap & 0x0010)
        
        if not privacy:
            return "OPEN"
        
        # Check for RSN (WPA2)
        if pkt.haslayer(Dot11Elt):
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 48:  # RSN Information
                    return "WPA2"
                elif elt.ID == 221:  # Vendor Specific (WPA)
                    if elt.info[:4] == b'\x00\x50\xf2\x01':
                        return "WPA"
                elt = elt.payload.getlayer(Dot11Elt)
        
        return "WEP"
    
    # ========================================================================
    # DETECTION METHODS
    # ========================================================================
    
    def detect_deauth_attack(self, pkt):
        """Detect deauthentication flood attacks"""
        if not pkt.haslayer(Dot11Deauth):
            return
        
        src = pkt.addr2 or 'unknown'
        dst = pkt.addr1 or 'broadcast'
        bssid = pkt.addr3 or 'unknown'
        now = time.time()
        
        # Track combined deauth/disassoc for WPA downgrade detection
        sig_key = f"{src}:{dst}"
        self.combined_attack_signatures[sig_key]['deauth'] += 1
        self.combined_attack_signatures[sig_key]['last_update'] = now
        
        # Track deauth frames from this source
        dq = self.deauth_counters[src]
        dq.append(now)
        
        # Remove old entries outside time window
        while dq and dq[0] < now - DEAUTH_WINDOW:
            dq.popleft()
        
        # Check if threshold exceeded
        if len(dq) >= DEAUTH_THRESHOLD:
            # Check for null MAC (TKIPTUN-NG signature)
            if '00:00:00:00:00:00' in [src, dst, bssid]:
                self._create_alert(
                    attack_type='tkiptun_deauth',
                    severity='high',
                    src_mac=src,
                    dst_mac=dst,
                    bssid=bssid,
                    frame_count=len(dq),
                    attack_signature='TKIPTUN-NG',
                    signal_strength=self._get_signal_strength(pkt),
                    details=f'TKIPTUN-NG signature detected: Deauth with null MAC ({len(dq)} frames in {DEAUTH_WINDOW}s)'
                )
            else:
                self._create_alert(
                    attack_type='deauth_flood',
                    severity='high',
                    src_mac=src,
                    dst_mac=dst,
                    bssid=bssid,
                    frame_count=len(dq),
                    attack_signature='WPA_HANDSHAKE_ATTACK',
                    signal_strength=self._get_signal_strength(pkt),
                    details=f'Deauthentication flood detected: {len(dq)} frames in {DEAUTH_WINDOW}s from {src} (possible WPA handshake capture attempt)'
                )
            dq.clear()
    
    def detect_disassoc_attack(self, pkt):
        """Detect disassociation flood attacks"""
        if not pkt.haslayer(Dot11Disas):
            return
        
        src = pkt.addr2 or 'unknown'
        dst = pkt.addr1 or 'broadcast'
        bssid = pkt.addr3 or 'unknown'
        now = time.time()
        
        # Track combined deauth/disassoc for WPA downgrade detection
        sig_key = f"{src}:{dst}"
        self.combined_attack_signatures[sig_key]['disassoc'] += 1
        self.combined_attack_signatures[sig_key]['last_update'] = now
        
        dq = self.disassoc_counters[src]
        dq.append(now)
        
        while dq and dq[0] < now - DISASSOC_WINDOW:
            dq.popleft()
        
        if len(dq) >= DISASSOC_THRESHOLD:
            # Check for WPA downgrade attack (MDK3 signature)
            sig = self.combined_attack_signatures[sig_key]
            if sig['deauth'] >= WPA_DOWNGRADE_THRESHOLD and sig['disassoc'] >= WPA_DOWNGRADE_THRESHOLD:
                self._create_alert(
                    attack_type='wpa_downgrade',
                    severity='critical',
                    src_mac=src,
                    dst_mac=dst,
                    bssid=bssid,
                    frame_count=sig['deauth'] + sig['disassoc'],
                    attack_signature='MDK3_WPA_DOWNGRADE',
                    signal_strength=self._get_signal_strength(pkt),
                    details=f'WPA downgrade attack detected (MDK3): {sig["deauth"]} deauth + {sig["disassoc"]} disassoc frames'
                )
                # Clear signature
                self.combined_attack_signatures[sig_key]['deauth'] = 0
                self.combined_attack_signatures[sig_key]['disassoc'] = 0
            else:
                self._create_alert(
                    attack_type='disassoc_flood',
                    severity='high',
                    src_mac=src,
                    dst_mac=dst,
                    bssid=bssid,
                    frame_count=len(dq),
                    signal_strength=self._get_signal_strength(pkt),
                    details=f'Disassociation flood detected: {len(dq)} frames in {DISASSOC_WINDOW}s from {src}'
                )
            dq.clear()
    
    def detect_auth_dos(self, pkt):
        """Detect authentication DoS attacks"""
        if not pkt.haslayer(Dot11Auth):
            return
        
        src = pkt.addr2 or 'unknown'
        dst = pkt.addr1 or 'broadcast'
        bssid = pkt.addr3 or 'unknown'
        now = time.time()
        
        dq = self.auth_counters[src]
        dq.append(now)
        
        while dq and dq[0] < now - AUTH_WINDOW:
            dq.popleft()
        
        if len(dq) >= AUTH_THRESHOLD:
            # Check if targeting multiple clients (MDK3 signature)
            unique_dsts = len(set([pkt.addr1 for pkt in dq if hasattr(pkt, 'addr1')]))
            
            if unique_dsts > 10:
                attack_sig = 'MDK3_AUTH_DOS'
                details = f'Authentication DoS detected (MDK3): {len(dq)} auth frames to {unique_dsts} different clients'
            else:
                attack_sig = 'AIREPLAY_WPA_MIGRATION'
                details = f'Possible WPA migration attack (Aireplay-NG): {len(dq)} auth frames in {AUTH_WINDOW}s'
            
            self._create_alert(
                attack_type='auth_dos',
                severity='high',
                src_mac=src,
                dst_mac=dst,
                bssid=bssid,
                frame_count=len(dq),
                attack_signature=attack_sig,
                signal_strength=self._get_signal_strength(pkt),
                details=details
            )
            dq.clear()
    
    def detect_assoc_flood(self, pkt):
        """Detect association flooding attacks"""
        if not pkt.haslayer(Dot11AssoReq) and not pkt.haslayer(Dot11ReassoReq):
            return
        
        src = pkt.addr2 or 'unknown'
        dst = pkt.addr1 or 'broadcast'
        bssid = pkt.addr3 or 'unknown'
        now = time.time()
        
        dq = self.assoc_counters[src]
        dq.append(now)
        
        while dq and dq[0] < now - ASSOC_WINDOW:
            dq.popleft()
        
        if len(dq) >= ASSOC_THRESHOLD:
            self._create_alert(
                attack_type='assoc_flood',
                severity='medium',
                src_mac=src,
                dst_mac=dst,
                bssid=bssid,
                frame_count=len(dq),
                attack_signature='ASSOC_FLOODING',
                signal_strength=self._get_signal_strength(pkt),
                details=f'Association flood detected: {len(dq)} association requests in {ASSOC_WINDOW}s from {src}'
            )
            dq.clear()
    
    def detect_wep_attacks(self, pkt):
        """Detect various WEP attacks (chopchop, fragmentation)"""
        if not pkt.haslayer(Dot11):
            return
        
        src = pkt.addr2
        dst = pkt.addr1
        now = time.time()
        
        if not src:
            return
        
        # Detect broadcast data packets (general WEP attack indicator)
        if dst == 'ff:ff:ff:ff:ff:ff' and pkt.type == 2:  # Data frame
            dq = self.wep_data_counters[src]
            dq.append(now)
            
            while dq and dq[0] < now - WEP_DATA_WINDOW:
                dq.popleft()
            
            if len(dq) >= WEP_BROADCAST_DATA:
                self._create_alert(
                    attack_type='wep_broadcast_data',
                    severity='high',
                    src_mac=src,
                    dst_mac=dst,
                    bssid=pkt.addr3,
                    frame_count=len(dq),
                    attack_signature='WEP_ATTACK',
                    signal_strength=self._get_signal_strength(pkt),
                    details=f'WEP attack detected: {len(dq)} broadcast data frames in {WEP_DATA_WINDOW}s (possible ARP replay/injection)'
                )
                dq.clear()
        
        # Detect Korek chopchop attack (data frames with specific patterns)
        # Type 2 (Data), Subtype 0, to non-broadcast, with FF in last octets
        if pkt.type == 2 and dst and dst.startswith('ff:') and not dst.startswith('ff:ff:ff'):
            dq = self.chopchop_counters[src]
            dq.append(now)
            
            while dq and dq[0] < now - WEP_DATA_WINDOW:
                dq.popleft()
            
            if len(dq) >= CHOPCHOP_THRESHOLD:
                self._create_alert(
                    attack_type='chopchop_attack',
                    severity='high',
                    src_mac=src,
                    dst_mac=dst,
                    bssid=pkt.addr3,
                    frame_count=len(dq),
                    attack_signature='KOREK_CHOPCHOP',
                    signal_strength=self._get_signal_strength(pkt),
                    details=f'Korek chopchop attack detected: {len(dq)} chopchop frames from {src} (WEP key recovery)'
                )
                dq.clear()
        
        # Detect fragmentation PRGA attack (subtype 0x94 pattern)
        # This is indicated by fragmented data frames with specific flags
        if pkt.type == 2 and pkt.FCfield & 0x04:  # More fragments flag
            dq = self.fragmentation_counters[src]
            dq.append(now)
            
            while dq and dq[0] < now - WEP_DATA_WINDOW:
                dq.popleft()
            
            if len(dq) >= FRAGMENTATION_THRESHOLD:
                self._create_alert(
                    attack_type='fragmentation_prga',
                    severity='high',
                    src_mac=src,
                    dst_mac=dst,
                    bssid=pkt.addr3,
                    frame_count=len(dq),
                    attack_signature='FRAGMENTATION_PRGA',
                    signal_strength=self._get_signal_strength(pkt),
                    details=f'Fragmentation PRGA attack detected: {len(dq)} fragmented frames from {src} (WEP keystream recovery)'
                )
                dq.clear()
        
        # Detect wesside-ng (multicast address pattern 01:00:5e:xx:xx:xx)
        """if dst and dst.startswith('01:00:5e:'):
            dq = self.wep_data_counters[f"{src}_wesside"]
            dq.append(now)
            
            while dq and dq[0] < now - WEP_DATA_WINDOW:
                dq.popleft()
            
            if len(dq) >= 5:
                self._create_alert(
                    attack_type='wesside_ng',
                    severity='critical',
                    src_mac=src,
                    dst_mac=dst,
                    bssid=pkt.addr3,
                    frame_count=len(dq),
                    attack_signature='WESSIDE_NG',
                    signal_strength=self._get_signal_strength(pkt),
                    details=f'Wesside-NG attack detected: {len(dq)} multicast frames from {src} (automated WEP cracking)'
                )
                dq.clear()
    
    def detect_tkip_michael(self, pkt):
        #Detect TKIP Michael shutdown exploitation (MDK3)
        if not pkt.haslayer(Dot11):
            return
        
        src = pkt.addr2
        if not src:
            return
        
        # MDK3 Michael shutdown uses MAC addresses ending in 00:00:00
        if src.endswith(':00:00:00'):
            now = time.time()
            dq = self.tkip_michael_counters[src]
            dq.append(now)
            
            while dq and dq[0] < now - 30:
                dq.popleft()
            
            if len(dq) >= TKIP_MICHAEL_THRESHOLD:
                self._create_alert(
                    attack_type='tkip_michael_exploit',
                    severity='critical',
                    src_mac=src,
                    bssid=pkt.addr3,
                    frame_count=len(dq),
                    attack_signature='MDK3_MICHAEL_SHUTDOWN',
                    signal_strength=self._get_signal_strength(pkt),
                    details=f'TKIP Michael shutdown exploitation detected (MDK3): {len(dq)} frames with spoofed MAC pattern'
                )
                dq.clear()
    
    def detect_qos_tkiptun(self, pkt):
        #Detect TKIPTUN-NG attack via QoS data patterns
        if not pkt.haslayer(Dot11QoS):
            return
        
        src = pkt.addr2
        dst = pkt.addr1
        
        if not src or not dst:
            return
        
        # TKIPTUN-NG uses specific QoS patterns
        now = time.time()
        dq = self.qos_data_counters[src]
        dq.append(now)
        
        while dq and dq[0] < now - 10:
            dq.popleft()
        
        # Even 1 QoS frame can be suspicious with TKIP
        if len(dq) >= QOS_DATA_THRESHOLD:
            # Check if BSSID uses TKIP
            bssid = pkt.addr3
            if bssid in self.known_aps:
                encryption = self.known_aps[bssid].get('encryption', '')
                if 'WPA' in encryption:  # TKIP is WPA
                    self._create_alert(
                        attack_type='tkiptun_ng',
                        severity='high',
                        src_mac=src,
                        dst_mac=dst,
                        bssid=bssid,
                        frame_count=len(dq),
                        attack_signature='TKIPTUN_NG',
                        signal_strength=self._get_signal_strength(pkt),
                        details=f'TKIPTUN-NG attack detected: Suspicious QoS data pattern on TKIP network'
                    )
                    dq.clear()"""
    
    def detect_wps_bruteforce(self, pkt):
        """Detect WPS brute force attacks (Reaver/Bully)"""
        if not pkt.haslayer(EAPOL):
            return
        
        src = pkt.addr2 or 'unknown'
        dst = pkt.addr1 or 'unknown'
        bssid = pkt.addr3 or 'unknown'
        now = time.time()
        
        dq = self.eap_counters[f"{src}:{dst}"]
        dq.append(now)
        
        while dq and dq[0] < now - WPS_EAP_WINDOW:
            dq.popleft()
        
        if len(dq) >= WPS_EAP_THRESHOLD:
            self._create_alert(
                attack_type='wps_bruteforce',
                severity='high',
                src_mac=src,
                dst_mac=dst,
                bssid=bssid,
                frame_count=len(dq),
                attack_signature='WPS_PIN_ATTACK',
                signal_strength=self._get_signal_strength(pkt),
                details=f'WPS brute force detected: {len(dq)} EAP exchanges in {WPS_EAP_WINDOW}s (Reaver/Bully attack)'
            )
            dq.clear()
    
    def detect_probe_abuse(self, pkt):
        """Detect probe request/response abuse"""
        if not pkt.haslayer(Dot11ProbeReq):
            return
        
        src = pkt.addr2 or 'unknown'
        ssid = self._get_ssid(pkt) or '<broadcast>'
        now = time.time()
        
        # Track probing devices
        if not self.hide_probes and ssid != '<broadcast>':
            self.probing_devices[src].add(ssid)
            self.db.update_probing_device(src, ssid)
        
        dq = self.probe_counters[src]
        dq.append(now)
        
        while dq and dq[0] < now - PROBE_WINDOW:
            dq.popleft()
        
        if len(dq) >= PROBE_THRESHOLD:
            probed_ssids = ', '.join(list(self.probing_devices[src])[:5])
            self._create_alert(
                attack_type='probe_flood',
                severity='medium',
                src_mac=src,
                ssid=probed_ssids,
                frame_count=len(dq),
                signal_strength=self._get_signal_strength(pkt),
                details=f'Probe request flood: {len(dq)} probes in {PROBE_WINDOW}s from {src} (SSIDs: {probed_ssids})'
            )
            dq.clear()
    
    def detect_rogue_ap(self, pkt):
        """Detect rogue APs and evil twin attacks"""
        if not pkt.haslayer(Dot11Beacon):
            return
        
        bssid = pkt.addr2 or pkt.addr3
        if not bssid:
            return
        
        ssid = self._get_ssid(pkt)
        if not ssid:
            ssid = '<hidden>'
        
        channel = self._get_channel(pkt)
        signal = self._get_signal_strength(pkt)
        encryption = self._get_encryption(pkt)
        now = time.time()
        
        # Track beacon rate for this BSSID
        beacon_times = self.beacon_counters[bssid]
        beacon_times.append(now)
        
        # Keep only last 2 seconds of beacons
        while beacon_times and beacon_times[0] < now - 2:
            beacon_times.popleft()
        
        # Check for beacon flooding (MDK3 signature)
        if len(beacon_times) > BEACON_RATE_THRESHOLD:
            self._create_alert(
                attack_type='beacon_flood',
                severity='high',
                src_mac=bssid,
                bssid=bssid,
                ssid=ssid,
                channel=channel,
                frame_count=len(beacon_times),
                attack_signature='MDK3_BEACON_FLOOD',
                signal_strength=signal,
                details=f'Beacon flooding detected (MDK3): {len(beacon_times)} beacons in 2s from {bssid} (normal ~10)'
            )
            beacon_times.clear()
        
        # Update AP database
        self.db.update_ap(bssid, ssid, channel, encryption)
        
        # Track AP in network map
        if bssid not in self.known_aps:
            self.known_aps[bssid] = {
                'ssid': ssid,
                'channel': channel,
                'encryption': encryption,
                'first_seen': now,
                'last_seen': now,
                'ssid_history': [ssid]
            }
        else:
            ap_info = self.known_aps[bssid]
            ap_info['last_seen'] = now
            
            # Detect SSID change (suspicious)
            if ap_info['ssid'] != ssid and ssid != '<hidden>':
                self._create_alert(
                    attack_type='ssid_change',
                    severity='high',
                    src_mac=bssid,
                    bssid=bssid,
                    ssid=ssid,
                    channel=channel,
                    attack_signature='AP_SSID_CHANGE',
                    signal_strength=signal,
                    details=f'AP SSID change detected: {bssid} changed from "{ap_info["ssid"]}" to "{ssid}"'
                )
                ap_info['ssid'] = ssid
                ap_info['ssid_history'].append(ssid)
        
        # Detect multiple SSIDs from same BSSID (Rogue AP indicator)
        if bssid in self.known_aps:
            ssid_count = len(set(self.known_aps[bssid]['ssid_history']))
            if ssid_count >= BEACON_FLOOD_THRESHOLD:
                ssids = ', '.join(self.known_aps[bssid]['ssid_history'][:10])
                self._create_alert(
                    attack_type='rogue_ap_multiple_ssid',
                    severity='critical',
                    src_mac=bssid,
                    bssid=bssid,
                    ssid=ssid,
                    channel=channel,
                    attack_signature='ROGUE_AP',
                    signal_strength=signal,
                    details=f'Rogue AP detected: {bssid} broadcasting {ssid_count} different SSIDs ({ssids})'
                )
        
        # Detect evil twin (multiple BSSIDs with same SSID)
        if ssid != '<hidden>':
            existing_bssids = self.ssid_to_bssids[ssid]
            if bssid not in existing_bssids and len(existing_bssids) > 0:
                other_bssids = ', '.join(list(existing_bssids)[:3])
                self._create_alert(
                    attack_type='evil_twin',
                    severity='critical',
                    src_mac=bssid,
                    bssid=bssid,
                    ssid=ssid,
                    channel=channel,
                    attack_signature='EVIL_TWIN',
                    signal_strength=signal,
                    details=f'Evil twin detected: New BSSID {bssid} for SSID "{ssid}" (existing: {other_bssids})'
                )
            existing_bssids.add(bssid)
    
    def detect_client_roaming(self, pkt):
        """Detect suspicious client roaming (potential rogue AP connection)"""
        # Association request/response
        if pkt.haslayer(Dot11AssoReq) or pkt.haslayer(Dot11AssoResp):
            client_mac = pkt.addr2 if pkt.haslayer(Dot11AssoReq) else pkt.addr1
            bssid = pkt.addr1 if pkt.haslayer(Dot11AssoReq) else pkt.addr2
            
            if not client_mac or not bssid:
                return
            
            # Get SSID
            ssid = self._get_ssid(pkt)
            if not ssid and bssid in self.known_aps:
                ssid = self.known_aps[bssid].get('ssid')
            
            # Check if client was previously associated with different BSSID
            prev = self.db.get_client_previous_bssid(client_mac)
            
            if prev and prev[0] != bssid:
                prev_bssid, prev_ssid = prev
                
                # Update association
                self.db.update_client_association(client_mac, bssid, ssid or 'unknown')
                
                # Alert if SSID is the same but BSSID changed (rogue AP indicator)
                if ssid and prev_ssid and ssid == prev_ssid:
                    self._create_alert(
                        attack_type='client_roaming_suspicious',
                        severity='medium',
                        src_mac=client_mac,
                        bssid=bssid,
                        ssid=ssid,
                        attack_signature='POSSIBLE_ROGUE_AP',
                        signal_strength=self._get_signal_strength(pkt),
                        details=f'Client {client_mac} switched from BSSID {prev_bssid} to {bssid} (same SSID "{ssid}") - possible rogue AP'
                    )
            elif not prev and bssid and ssid:
                # New association
                self.db.update_client_association(client_mac, bssid, ssid)
    
    def detect_mac_spoofing(self, pkt):
        """Detect potential MAC address spoofing"""
        if not pkt.haslayer(Dot11):
            return
        
        src = pkt.addr2
        if not src:
            return
        
        # Extract OUI (first 3 octets)
        oui = ':'.join(src.split(':')[:3]).upper()
        
        # Track vendor changes for source MAC
        vendors = self.mac_vendors[src]
        
        # Detect obvious spoofed patterns
        if src.startswith('00:00:00') or src.startswith('ff:ff:ff'):
            if src != 'ff:ff:ff:ff:ff:ff':  # Not broadcast
                self._create_alert(
                    attack_type='mac_spoofing',
                    severity='medium',
                    src_mac=src,
                    details=f'Suspicious MAC pattern: {src} (likely spoofed/fabricated)'
                )
                return
        
        # Check for OUI changes (definite spoofing)
        if len(vendors) > 0 and oui not in vendors:
            old_vendors = ', '.join(list(vendors)[:3])
            self._create_alert(
                attack_type='mac_spoofing',
                severity='high',
                src_mac=src,
                attack_signature='OUI_CHANGE',
                details=f'MAC OUI changed for {src}: was {old_vendors}, now {oui} (MAC spoofing)'
            )
        
        vendors.add(oui)
    
    def packet_handler(self, pkt):
        """Main packet handler - runs all detection methods"""
        try:
            if not pkt.haslayer(Dot11):
                return
            
            self.frame_count += 1
            
            # Run all detection methods
            self.detect_deauth_attack(pkt)
            self.detect_disassoc_attack(pkt)
            self.detect_auth_dos(pkt)
            self.detect_assoc_flood(pkt)
            self.detect_wep_attacks(pkt)
            #self.detect_tkip_michael(pkt)
            #self.detect_qos_tkiptun(pkt)
            self.detect_wps_bruteforce(pkt)
            self.detect_probe_abuse(pkt)
            self.detect_rogue_ap(pkt)
            self.detect_client_roaming(pkt)
            self.detect_mac_spoofing(pkt)
            
            # Log progress every 5000 frames
            if self.frame_count % 5000 == 0:
                elapsed = time.time() - self.start_time
                rate = self.frame_count / elapsed
                logger.info(f"Processed {self.frame_count} frames ({rate:.1f} fps), {self.alert_count} alerts")
        
        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)
    
    def start(self):
        """Start WIDS detection"""
        logger.info("=" * 80)
        logger.info("WIRELESS INTRUSION DETECTION SYSTEM (WIDS)")
        logger.info("=" * 80)
        logger.info(f"Interface: {self.interface}")
        logger.info(f"Log directory: {self.log_dir}")
        logger.info(f"Database: {os.path.join(self.log_dir, 'wids_alerts.db')}")
        logger.info("")
        logger.info("Detection capabilities:")
        logger.info("  [+] WEP attacks (chopchop, fragmentation, broadcast)")
        logger.info("  [+] WPA/WPA2 attacks (handshake capture, downgrade)")
        logger.info("  [+] WPS brute force (Reaver/Bully)")
        logger.info("  [+] Deauth/Disassoc floods")
        logger.info("  [+] Authentication DoS (MDK3, Aireplay)")
        logger.info("  [+] Association flooding")
        logger.info("  [+] Evil twin / Rogue AP detection")
        logger.info("  [+] Beacon flooding (MDK3)")
        #logger.info("  [+] TKIP attacks (Michael shutdown, TKIPTUN-NG)")
        logger.info("  [+] MAC spoofing")
        logger.info("  [+] Client probing and roaming")
        logger.info("")
        logger.info("Thresholds:")
        logger.info(f"  - Deauth: {DEAUTH_THRESHOLD} frames in {DEAUTH_WINDOW}s")
        logger.info(f"  - Disassoc: {DISASSOC_THRESHOLD} frames in {DISASSOC_WINDOW}s")
        logger.info(f"  - Auth DoS: {AUTH_THRESHOLD} frames in {AUTH_WINDOW}s")
        logger.info(f"  - Assoc flood: {ASSOC_THRESHOLD} frames in {ASSOC_WINDOW}s")
        logger.info(f"  - Probe flood: {PROBE_THRESHOLD} frames in {PROBE_WINDOW}s")
        logger.info(f"  - WEP broadcast: {WEP_BROADCAST_DATA} frames in {WEP_DATA_WINDOW}s")
        logger.info(f"  - Beacon flood: >{BEACON_RATE_THRESHOLD} beacons/sec")
        logger.info("=" * 80)
        logger.info("Starting packet capture... (Press Ctrl+C to stop)")
        logger.info("")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=False
            )
        except KeyboardInterrupt:
            logger.info("\n\nStopping Enhanced WIDS...")
            self.print_statistics()
        except Exception as e:
            logger.error(f"Capture error: {e}", exc_info=True)
        finally:
            self.db.close()
    
    def print_statistics(self):
        """Print comprehensive detection statistics"""
        elapsed = time.time() - self.start_time
        
        logger.info("\n" + "=" * 80)
        logger.info("WIDS STATISTICS")
        logger.info("=" * 80)
        logger.info(f"Runtime: {elapsed:.1f} seconds")
        logger.info(f"Total frames processed: {self.frame_count}")
        logger.info(f"Average frame rate: {self.frame_count / elapsed:.1f} fps")
        logger.info(f"Total alerts generated: {self.alert_count}")
        logger.info(f"Known APs tracked: {len(self.known_aps)}")
        logger.info(f"Unique SSIDs seen: {len(self.ssid_to_bssids)}")
        logger.info(f"Probing devices: {len(self.probing_devices)}")
        logger.info("")
        logger.info("Output files:")
        logger.info(f"  - JSON log: {os.path.join(self.log_dir, 'wids_alerts.json')}")
        if self.enable_text_log:
            logger.info(f"  - Text log: {os.path.join(self.log_dir, 'wids_events.log')}")
        logger.info(f"  - Database: {os.path.join(self.log_dir, 'wids_alerts.db')}")
        logger.info("=" * 80)


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# def check_root():
#     """Check if running as root"""
#     if os.geteuid() != 0:
#         logger.error("This script must be run as root (sudo)")
#         logger.error("Packet capture requires root privileges")
#         return False
#     return True

def check_root():
    system = platform.system()

    if system == "Windows":
        return True
    else:
        try:
            if os.geteuid() != 0:
                print("You need root privileges to run this program.")
                return False
        except AttributeError:
            return True
    return True

def check_interface(interface: str) -> bool:
    """Check if interface exists"""
    interfaces_path = "/sys/class/net"
    if not os.path.exists(os.path.join(interfaces_path, interface)):
        logger.error(f"Interface {interface} not found")
        logger.error("\nAvailable interfaces:")
        os.system("ip link show | grep -E '^[0-9]+:' | awk '{print $2}' | sed 's/:$//'")
        return False
    return True


def check_monitor_mode(interface: str) -> bool:
    """Check if interface is in monitor mode"""
    try:
        result = subprocess.run(
            ['iwconfig', interface],
            capture_output=True,
            text=True
        )
        return 'Mode:Monitor' in result.stdout
    except:
        return False


def enable_monitor_mode(interface: str) -> Optional[str]:
    """Enable monitor mode on interface"""
    logger.info(f"Attempting to enable monitor mode on {interface}...")
    
    # Try using airmon-ng
    try:
        # Kill interfering processes
        subprocess.run(['airmon-ng', 'check', 'kill'], 
                      capture_output=True, check=False)
        
        # Start monitor mode
        result = subprocess.run(
            ['airmon-ng', 'start', interface],
            capture_output=True,
            text=True
        )
        
        # airmon-ng usually creates wlan0mon from wlan0
        monitor_interface = interface + 'mon'
        
        if check_interface(monitor_interface):
            logger.info(f"[+] Monitor mode enabled: {monitor_interface}")
            return monitor_interface
        
    except FileNotFoundError:
        logger.warning("airmon-ng not found, trying manual method...")
    
    # Try manual method
    try:
        subprocess.run(['ifconfig', interface, 'down'], check=True)
        subprocess.run(['iwconfig', interface, 'mode', 'monitor'], check=True)
        subprocess.run(['ifconfig', interface, 'up'], check=True)
        
        if check_monitor_mode(interface):
            logger.info(f"[+] Monitor mode enabled: {interface}")
            return interface
    except Exception as e:
        logger.error(f"Manual method failed: {e}")
    
    logger.error("Failed to enable monitor mode")
    logger.error("Try manually: sudo airmon-ng start wlan0")
    return None


def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully"""
    print("\n\nReceived interrupt signal, shutting down...")
    sys.exit(0)


# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    # Root / Admin privilege check
    if not check_root():
        sys.exit(1)
    # --- rest of your WIDS start logic ---

    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(
        description='Enhanced Wireless Intrusion Detection System (WIDS)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-enable monitor mode and run
  sudo python3 enhanced_wids.py -i wlan0 --enable-monitor

  # Run on existing monitor interface
  sudo python3 enhanced_wids.py -i wlan0mon

  # Custom log directory
  sudo python3 enhanced_wids.py -i wlan0mon -l /var/log/wids

  # Hide probe requests from output
  sudo python3 enhanced_wids.py -i wlan0mon --hide-probes

  # View live JSON alerts
  tail -f /opt/wids/wids_alerts.json | jq '.'

  # Query database
  sqlite3 /opt/wids/wids_alerts.db "SELECT * FROM wireless_alerts ORDER BY timestamp DESC LIMIT 10"

Detection Capabilities:
  âœ“ WEP Attacks: Chopchop, Fragmentation, Broadcast injection
  âœ“ WPA/WPA2: Handshake capture, Downgrade attacks (MDK3)
  âœ“ WPS: Brute force detection (Reaver/Bully)
  âœ“ DoS Attacks: Deauth/Disassoc floods, Auth DoS, Association flooding
  âœ“ Rogue APs: Evil twin detection, Multiple SSID broadcasting
  âœ“ TKIP Attacks: Michael shutdown exploitation, TKIPTUN-NG
  âœ“ Network Topology: Client roaming, MAC spoofing, Vendor analysis
  âœ“ Beacon Flooding: MDK3 signature detection
        """
    )
    parser.add_argument('-i', '--interface', required=True, 
                       help='Wireless interface (e.g., wlan0, wlan0mon)')
    parser.add_argument('-l', '--log-dir', default='/opt/wids',
                       help='Log directory (default: /opt/wids)')
    parser.add_argument('--enable-monitor', action='store_true',
                       help='Automatically enable monitor mode')
    parser.add_argument('--no-text-log', action='store_true',
                       help='Disable text log file')
    parser.add_argument('--hide-probes', action='store_true',
                       help='Hide probe request detection from output')
    
    args = parser.parse_args()
    
    # Display banner
    print("\n" + "=" * 80)
    print(" â–‘â–ˆâ–ˆ       â–‘â–ˆâ–ˆ â–‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ     â–‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ   \n"
          " â–‘â–ˆâ–ˆ       â–‘â–ˆâ–ˆ   â–‘â–ˆâ–ˆ  â–‘â–ˆâ–ˆ   â–‘â–ˆâ–ˆ   â–‘â–ˆâ–ˆ   â–‘â–ˆâ–ˆ  \n"
          " â–‘â–ˆâ–ˆ  â–‘â–ˆâ–ˆ  â–‘â–ˆâ–ˆ   â–‘â–ˆâ–ˆ  â–‘â–ˆâ–ˆ    â–‘â–ˆâ–ˆ â–‘â–ˆâ–ˆ         \n"
          " â–‘â–ˆâ–ˆ â–‘â–ˆâ–ˆâ–ˆâ–ˆ â–‘â–ˆâ–ˆ   â–‘â–ˆâ–ˆ  â–‘â–ˆâ–ˆ    â–‘â–ˆâ–ˆ  â–‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ  \n"
          " â–‘â–ˆâ–ˆâ–‘â–ˆâ–ˆ â–‘â–ˆâ–ˆâ–‘â–ˆâ–ˆ   â–‘â–ˆâ–ˆ  â–‘â–ˆâ–ˆ    â–‘â–ˆâ–ˆ         â–‘â–ˆâ–ˆ \n"
          " â–‘â–ˆâ–ˆâ–ˆâ–ˆ   â–‘â–ˆâ–ˆâ–ˆâ–ˆ   â–‘â–ˆâ–ˆ  â–‘â–ˆâ–ˆ   â–‘â–ˆâ–ˆ   â–‘â–ˆâ–ˆ   â–‘â–ˆâ–ˆ  \n"
          " â–‘â–ˆâ–ˆâ–ˆ     â–‘â–ˆâ–ˆâ–ˆ â–‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ     â–‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ   \n");

    print(" WIRELESS INTRUSION DETECTION SYSTEM")
    print("=" * 80 + "\n")
    
    # Check root privileges
    if not check_root():
        return 1
    
    # Check interface exists
    interface = args.interface
    if not check_interface(interface):
        return 1
    
    # Enable monitor mode if requested
    if args.enable_monitor:
        if not check_monitor_mode(interface):
            monitor_interface = enable_monitor_mode(interface)
            if monitor_interface:
                interface = monitor_interface
            else:
                logger.error("Failed to enable monitor mode")
                return 1
        else:
            logger.info(f"âœ“ {interface} is already in monitor mode")
    else:
        # Verify monitor mode
        if 'mon' in interface.lower() or check_monitor_mode(interface):
            logger.info(f"âœ“ {interface} is in monitor mode")
        else:
            logger.warning(f"âš   Warning: {interface} may not be in monitor mode")
            logger.warning("  Detection may not work properly without monitor mode")
            logger.warning("  Use --enable-monitor flag or manually enable:")
            logger.warning("  sudo airmon-ng start wlan0")
            response = input("\nContinue anyway? (y/N): ")
            if response.lower() != 'y':
                return 1
    
    # Create output directory
    os.makedirs(args.log_dir, exist_ok=True)
    
    # Create and start enhanced detector
    detector = WIDSDetector(
        interface=interface,
        log_dir=args.log_dir,
        enable_text_log=not args.no_text_log,
        hide_probes=args.hide_probes
    )
    
    try:
        detector.start()
    except KeyboardInterrupt:
        print("\n\nShutting down gracefully...")
        detector.print_statistics()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
