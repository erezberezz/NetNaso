import requests
import folium
import pandas as pd
import subprocess
import platform
import socket
import re

def is_ipv6(address):
    #This func receives an address as its argument, checks if it's IPv6 or hostname inorder to handle tracert
    try:
        socket.inet_pton(socket.AF_INET6, address)  # Try to parse it as IPv6
        return True
    except socket.error:
        try:
            info = socket.getaddrinfo(address, None, socket.AF_INET6)
            return len(info) > 0
        except socket.gaierror:
            return False

def get_geoip(ip):
    #Fetch IP coordinates for each IP address
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()
        if data["status"] == "success":
            return data["lat"], data["lon"], f"{data['city']}, {data['country']}"
        return None, None, "Unknown"
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] GeoIP request failed: {e}")
        return None, None, "Unknown"

def traceroute(destination, max_hops=20):
    #Performs an ICMP traceroute and returns results, on a worldmap. supporting both IPv4 and IPv6 (using is_ipv6()).
    hop_data = []
    map_obj = folium.Map(location=[0, 0], zoom_start=2)

    system = platform.system()
    use_ipv6 = is_ipv6(destination)  # Check if IPv6 is needed

    # Select the correct command for the OS and IP version
    if system == "Windows":
        cmd = ["tracert", "-d", "-h", str(max_hops), destination] if not use_ipv6 else ["tracert", "-6", destination]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), destination] if not use_ipv6 else ["traceroute", "-6", "-n", "-m", str(max_hops), destination]

    try:
        print(f"Running command: {' '.join(cmd)}")  # Debugging print
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        for line in process.stdout:
            line = line.strip()
            print(f"Traceroute output: {line}")  # Debugging print

            #extract the last word of the line (IP address) using regex
            match = re.search(r"(\d+\.\d+\.\d+\.\d+|\[?[0-9a-fA-F:]+\]?)$", line)
            if match:
                hop_ip = match.group(1).strip("[]")  #remove square brackets from IPv6

                lat, lon, location = get_geoip(hop_ip)
                hop_number = len(hop_data) + 1
                rtt = re.findall(r"(\d+) ms", line)  #extract RTT if available
                rtt_value = f"{rtt[-1]} ms" if rtt else "N/A"

                hop_info = {
                    "Hop": hop_number,
                    "IP": hop_ip,
                    "Location": location,
                    "Lat": lat,
                    "Lon": lon,
                    "RTT": rtt_value
                }
                hop_data.append(hop_info)

                # Add numbered marker with detailed popup
                if lat and lon:
                    folium.Marker(
                        [lat, lon],
                        popup=(
                            f"<b>Hop {hop_number}</b><br>"
                            f"IP: {hop_ip}<br>"
                            f"Location: {location}<br>"
                            f"RTT: {rtt_value}"
                        ),
                        tooltip=f"Hop {hop_number}: {hop_ip}",
                        icon=folium.DivIcon(html=f"""
                            <div style="background-color:blue;color:white;padding:5px;
                            border-radius:50%;width:25px;height:25px;text-align:center;">
                                {hop_number}
                            </div>
                        """),
                    ).add_to(map_obj)


        if not hop_data:
            print("[ERROR] No valid hops found!")

        #save results
        df = pd.DataFrame(hop_data)
        df.to_csv("traceroute_results.csv", index=False)
        map_obj.save("traceroute_map.html")

        return hop_data

    except Exception as e:
        print(f"[ERROR] Traceroute failed: {e}")
        return []
