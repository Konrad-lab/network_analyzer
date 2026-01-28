import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                            QHBoxLayout, QPushButton, QTextEdit, QLabel,
                            QComboBox, QLineEdit, QMessageBox)
from PyQt5.QtCore import QTimer, pyqtSignal, QObject
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
import threading
import queue
import platform
import logging
import psutil

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PacketWorker(QObject):
    packet_received = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.capturing = False
        self.packet_queue = queue.Queue()
        
    def process_packet(self, packet):
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto
                
                info = f"Source: {src_ip} -> Destination: {dst_ip} | Protocol: {protocol}"
                
                if TCP in packet:
                    info += f" | TCP Port: {packet[TCP].sport}->{packet[TCP].dport}"
                elif UDP in packet:
                    info += f" | UDP Port: {packet[UDP].sport}->{packet[UDP].dport}"
                elif ICMP in packet:
                    info += " | ICMP"
                    
                self.packet_received.emit(info)
        except Exception as e:
            logger.error(f"Error analyzing packet: {str(e)}")

class NetworkAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Packet Analyzer")
        self.setGeometry(100, 100, 800, 600)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create controls
        controls_layout = QHBoxLayout()
        
        # Interface selection
        self.interface_combo = QComboBox()
        self.update_interfaces()
        controls_layout.addWidget(QLabel("Interface:"))
        controls_layout.addWidget(self.interface_combo)
        
        # Refresh interfaces button
        refresh_button = QPushButton("Refresh Interfaces")
        refresh_button.clicked.connect(self.update_interfaces)
        controls_layout.addWidget(refresh_button)
        
        # Filter input
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Enter filter (e.g., tcp port 80)")
        controls_layout.addWidget(QLabel("Filter:"))
        controls_layout.addWidget(self.filter_input)
        
        # Start/Stop button
        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.toggle_capture)
        controls_layout.addWidget(self.start_button)
        
        layout.addLayout(controls_layout)
        
        # Packet display
        self.packet_display = QTextEdit()
        self.packet_display.setReadOnly(True)
        layout.addWidget(self.packet_display)
        
        # Initialize worker
        self.worker = PacketWorker()
        self.worker.packet_received.connect(self.update_packet_display)
        
        # Initialize capture variables
        self.capturing = False
        self.capture_thread = None
        self.interface_ids = []  # ÚJ: ide kerülnek az NPF-azonosítók
        
    def update_interfaces(self):
        self.interface_combo.clear()
        self.interface_ids = []
        try:
            interfaces, ids = get_friendly_interfaces()
            if not interfaces:
                self.interface_combo.addItem("No interfaces found")
                self.interface_ids = []
            else:
                self.interface_combo.addItems(interfaces)
                self.interface_ids = ids
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not get network interfaces: {str(e)}")
            self.interface_combo.addItem("No interfaces found")
            self.interface_ids = []
            
    def toggle_capture(self):
        if not self.capturing:
            self.start_capture()
        else:
            self.stop_capture()
            
    def start_capture(self):
        try:
            self.capturing = True
            self.start_button.setText("Stop Capture")
            self.packet_display.clear()
            
            # Start capture thread
            self.capture_thread = threading.Thread(target=self.capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start capture: {str(e)}")
            self.capturing = False
            self.start_button.setText("Start Capture")
        
    def stop_capture(self):
        self.capturing = False
        self.start_button.setText("Start Capture")
        
    def capture_packets(self):
        def packet_callback(packet):
            if not self.capturing:
                return
            try:
                self.worker.process_packet(packet)
            except Exception as e:
                logger.error(f"Error processing packet: {str(e)}")
        
        idx = self.interface_combo.currentIndex()
        if idx < 0 or idx >= len(self.interface_ids):
            self.packet_display.append("No valid network interface selected!")
            return
        iface = self.interface_ids[idx]
        filter_str = self.filter_input.text()
        
        try:
            sniff(iface=iface, filter=filter_str, prn=packet_callback, store=0)
        except Exception as e:
            logger.error(f"Error in capture: {str(e)}")
            self.packet_display.append(f"Error: {str(e)}")
            
    def update_packet_display(self, packet_info):
        self.packet_display.append(packet_info)
            
    def closeEvent(self, event):
        self.capturing = False
        event.accept()

def get_friendly_interfaces():
    interfaces = get_if_list()
    addrs = psutil.net_if_addrs()
    friendly = []
    ids = []
    from scapy.arch.windows import get_windows_if_list
    scapy_ifs = get_windows_if_list()
    psutil_macs = {}
    for name, addr_list in addrs.items():
        for addr in addr_list:
            if addr.family == psutil.AF_LINK:
                psutil_macs[addr.address.lower()] = name
    for iface in interfaces:
        match = next((i for i in scapy_ifs if i['guid'] in iface or iface in i['name']), None)
        if match:
            mac = match.get('mac', '').lower()
            name = psutil_macs.get(mac, match.get('name', iface))
            friendly.append(f"{name} ({iface})")
            ids.append(iface)
        else:
            friendly.append(iface)
            ids.append(iface)
    return friendly, ids

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkAnalyzer()
    window.show()
    sys.exit(app.exec_()) 
