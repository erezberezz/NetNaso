import webbrowser
import requests
import speedtest
from PyQt6.QtCore import QTimer
import os
import sys
import threading
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QTextEdit,
    QLineEdit, QFileDialog,QSpinBox, QTableWidget, QTableWidgetItem, QTabWidget
)
from PyQt6.QtGui import QFont
import packetsniff
import traceroute
from net_graph import NetworkSpeedGraph


try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    web_view_available = True
except ImportError:
    print("[WARNING] QWebEngineView not found! Map display disabled.")
    web_view_available = False




class NetNasoGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.setWindowTitle("NetNaso")
        self.setGeometry(100, 100, 1000, 600)

        #Main Tab Widget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        #Packet Sniffer Tab
        self.packet_sniffer_tab = QWidget()
        self.setup_packet_sniffer_tab()
        self.tabs.addTab(self.packet_sniffer_tab, "Packet Sniffer")

        #Network Speed Graph Tab
        self.network_graph_tab = QWidget()
        self.setup_network_graph_tab()
        self.tabs.addTab(self.network_graph_tab, "Network Speed")


        #Traceroute Tab
        self.traceroute_tab = QWidget()
        self.setup_traceroute_tab()
        self.tabs.addTab(self.traceroute_tab, "Traceroute")

        #GeoIP tab
        self.geoip_tab=QWidget()
        self.setup_geoip_tab()
        self.tabs.addTab(self.geoip_tab,"GeoIP")



    ### PACKET SNIFFER TAB ###
    def setup_packet_sniffer_tab(self):
        #intilizes the packet sniffer tab
        layout = QVBoxLayout()

        #Start/Stop Sniffer Button
        self.sniff_button = QPushButton("Start Packet Sniffer")
        self.sniff_button.setCheckable(True)
        self.sniff_button.clicked.connect(self.toggle_sniffer)
        layout.addWidget(self.sniff_button)

        #Packet table
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(8)
        self.packet_table.setHorizontalHeaderLabels(["Time", "Src IP", "Src Host", "Dst IP", "Dst Host", "Type", "Protocol", "Port"])
        layout.addWidget(self.packet_table)

        self.packet_sniffer_tab.setLayout(layout)

        #Initializes Packet Sniffer
        self.sniffer = packetsniff.PacketSniffer()
        self.sniffer.packet_received.connect(self.update_packet_table)

    ### GEOIP TAB ###
    def setup_geoip_tab(self):
        # initializes the GeoIP tab
        layout = QVBoxLayout()

        self.geoip_input = QLineEdit()
        self.geoip_input.setPlaceholderText("Enter IP address")
        layout.addWidget(self.geoip_input)

        self.geoip_button = QPushButton("Lookup IP")
        self.geoip_button.clicked.connect(self.run_geoip_lookup)
        layout.addWidget(self.geoip_button)

        self.geoip_result = QTextEdit()
        layout.addWidget(self.geoip_result)

        self.geoip_tab.setLayout(layout)

    ### GEOIP FUNCTIONS ###
    def geoip_lookup(self, ip):
        #gets location from IP
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        return response if response["status"] == "success" else None

    def run_geoip_lookup(self):
        ip = self.geoip_input.text().strip()
        if not ip:
            self.geoip_result.setText("Please enter an IP!")
            return

        info = self.geoip_lookup(ip)
        if info:
            self.geoip_result.setText(
                f"Country: {info['country']}\nCity: {info['city']}\nISP: {info['isp']}\nCoords: {info['lat']}, {info['lon']}")
        else:
            self.geoip_result.setText("Invalid IP or API error.")

    ### TRACEROUTE TAB ###
    def setup_traceroute_tab(self):
        #initializes the traceroute tab
        layout = QVBoxLayout()

        #Input field for traceroute target
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Enter target IP/Domain (e.g., google.com)")
        self.input_field.setFont(QFont("Arial", 12))
        layout.addWidget(self.input_field)

        #Max hops selection
        self.max_hops_spinbox = QSpinBox()
        self.max_hops_spinbox.setRange(1, 50)  # Set range from 1 to 50 hops
        self.max_hops_spinbox.setValue(20)  # Default value
        self.max_hops_spinbox.setSuffix(" Hops")  # Show "Hops" next to the number
        layout.addWidget(self.max_hops_spinbox)

        #Run Traceroute button
        self.traceroute_button = QPushButton("Run Traceroute")
        self.traceroute_button.clicked.connect(self.start_traceroute)
        layout.addWidget(self.traceroute_button)

        #Traceroute table
        self.traceroute_table = QTableWidget()
        self.traceroute_table.setColumnCount(3)
        self.traceroute_table.setHorizontalHeaderLabels(["IP", "Location", "Coordinates"])
        layout.addWidget(self.traceroute_table)

        #Webview for the map
        if web_view_available:
            self.web_view = QWebEngineView()
            layout.addWidget(self.web_view)
        else:
            self.web_view = None  # Disable web view

        # Set Layout
        self.traceroute_tab.setLayout(layout)

    ### NETWORK GRAPH TAB ###
    def setup_network_graph_tab(self):
        #initalizes the network graph tab
        layout = QVBoxLayout()

        self.speed_graph = NetworkSpeedGraph()
        layout.addWidget(self.speed_graph)

        self.network_graph_tab.setLayout(layout)

        self.start_network_speed_updates()


    ### NET GRAPH FUNCTIONS ###
    def start_network_speed_updates(self):
        #strats speed testing at a set interval of 5 seconds
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.run_speedtest_thread)
        self.timer.start(5000)

    def run_speedtest_thread(self):
        #Runs speedtest in a seperate thread inorder to keep the UI responsive
        threading.Thread(target=self.get_speed, daemon=True).start()

    def get_speed(self):
        #preforms speedtest and updates the grapph
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            download_speed = st.download() / 1_000_000  # Convert to Mbps
            upload_speed = st.upload() / 1_000_000  # Convert to Mbps

            #Update the graph
            self.speed_graph.update_graph(download_speed, upload_speed)

        except Exception as e:
            print(f"[ERROR] Speed test failed: {e}")


    ### TRACEROUTE FUNCTIONS ###
    def start_traceroute(self):
        """Runs Traceroute in a Background Thread."""
        target = self.input_field.text().strip()
        max_hops = self.max_hops_spinbox.value()  # Get user-defined max hops

        if not target:
            print("[ERROR] No target entered.")  # Debugging print
            return

        print(f"Starting traceroute for {target} with max hops {max_hops}...")  # Debugging print
        threading.Thread(target=self.run_traceroute, args=(target, max_hops), daemon=True).start()


    #This function is in charge of running traceroute and updating the traceroute table
    def run_traceroute(self, destination, max_hops):
        print(f"Starting traceroute to {destination} with max {max_hops} hops...")  # Debugging print

        traceroute_data = traceroute.traceroute(destination, max_hops)
        print(f"Traceroute completed. Data received: {traceroute_data}")  # Debugging print

        if not traceroute_data:
            print("[ERROR] No traceroute data received.")  # Debugging print
            return

        #updates the traceroute table
        self.traceroute_table.setRowCount(0)
        for hop in traceroute_data:
            row_position = self.traceroute_table.rowCount()
            self.traceroute_table.insertRow(row_position)

            self.traceroute_table.setItem(row_position, 0, QTableWidgetItem(hop["IP"]))
            self.traceroute_table.setItem(row_position, 1, QTableWidgetItem(hop["Location"]))
            self.traceroute_table.setItem(row_position, 2, QTableWidgetItem(f"{hop['Lat']}, {hop['Lon']}"))

        #opens the map if available
        map_path = os.path.abspath("traceroute_map.html")
        if os.path.exists(map_path):
            print(f"Opening map: {map_path}")
            webbrowser.open(f"file:///{map_path}")  # Open in browser
        else:
            print("[ERROR] Map file not found.")


    #This function enables the pause and unpause of the network sniffing
    def toggle_sniffer(self):
        #starts\stops packet sniffing
        if self.sniff_button.isChecked():
            self.sniff_button.setText("Stop Packet Sniffer")
            self.sniff_button.setStyleSheet("background-color: green; color: white;")
            threading.Thread(target=self.sniffer.start_sniffing, daemon=True).start()
        else:
            self.sniff_button.setText("Start Packet Sniffer")
            self.sniff_button.setStyleSheet("background-color: red; color: white;")
            self.sniffer.stop_sniffing()

    #This function is incharge of updating the sniffed packet table
    def update_packet_table(self, timestamp, src_ip, src_host, dst_ip, dst_host, pkt_type, proto_type, port_info):
        row_position = self.packet_table.rowCount()
        self.packet_table.insertRow(row_position)

        self.packet_table.setItem(row_position, 0, QTableWidgetItem(timestamp))
        self.packet_table.setItem(row_position, 1, QTableWidgetItem(src_ip))
        self.packet_table.setItem(row_position, 2, QTableWidgetItem(src_host))
        self.packet_table.setItem(row_position, 3, QTableWidgetItem(dst_ip))
        self.packet_table.setItem(row_position, 4, QTableWidgetItem(dst_host))
        self.packet_table.setItem(row_position, 5, QTableWidgetItem(pkt_type))
        self.packet_table.setItem(row_position, 6, QTableWidgetItem(proto_type))
        self.packet_table.setItem(row_position, 7, QTableWidgetItem(port_info))

        #autoscroll to newest
        self.packet_table.scrollToBottom()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetNasoGUI()
    window.show()
    sys.exit(app.exec())
