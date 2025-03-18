# 💀CameraPhish💀

## 📜Description
CameraPhish is an advanced ethical cybersecurity tool that allows you to create realistic phishing pages  
to capture webcam images discreetly. It runs a Flask server and serves various phishing templates through  
a Cloudflare Tunnel, ensuring seamless connectivity.  

🔍The script is designed for educational & research purposes only to demonstrate phishing techniques  
used by attackers so that organizations can improve their security awareness.  

## 🔑Features
- ✅ 10+ Professional Phishing Templates (Meeting, Netflix, Scholarship, etc.)  
- ✅ Cloudflare Tunnel Integration (No need for port forwarding)  
- ✅ Captures Multiple Images (Automatically every few seconds)  
- ✅ IP Logging & Organization (Saves images in IP-based folders)  
- ✅ User-Friendly Console Interface (Easy template selection)  
- ✅ Automatic Cloudflare Installation (If missing)  
- ✅ Optimized for Mobile & PC (Fully responsive phishing pages)  

## 🚀Step-by-Step Guide in Linux Terminal !

Step 1: Update & upgrade your system  
>sudo apt update  

>sudo apt upgrade  

Step 2: install Dependencies  
>sudo apt install python3-flask  

>sudo apt install python3-requests  

Step 3: Clone the repository  
>git clone https://github.com/The-Real-Virus/CameraPhish.git  

Step 4: Go to the Tool Directory where u clone it  
>cd CameraPhish  

Step 5: After Completing the process now u can run script  
>python3 cameraphish.py  

## 💡Tips !
🌐 Must Use a URL shortener to make the tracking link look natural.  
⚡ Recommended URL shortners : (https://bitly.com/) , (https://grabify.link/) , (https://t.ly/).  
💀 Phishing link : "Send this link to victim".  
📊 Cloudflare links refresh some times , re run the script then.  
🔄 You can share one link to multiple victims.  
🛑 Use this responsibly – only on your own systems or with permission.  
⚡ Always check the tracking link in ur own browser first before sending to someone, make sure it is working.  
📊 images capture will be in capture_image directory with victims ip and logs will be created also.  
⚡ images will be capture continously untill u close the script or victim close the browser.  
🔄 it will download cloudflare only on first run if not already install.  

## 🤝Follow the Prompts !
1) This script is fully interactive! Just, Run it:  
2) Choose a phishing template (e.g., Birthday Wish, Online Meeting, etc.)  
3) Follow the on-screen instructions.  
4) The script starts Cloudflare Tunnel and generates a phishing link.  
5) Send the link to the target – Camera will capture images every few seconds.  

## ⚙️Troubleshooting

1) `Issue: Flask Not Found?:`  
- install the requirements (step 2 above).  

2) `Issue: Cloudflare link Not Working?:`  
- its due to cloudflare server down sometimes, run script after few time maybe hours...  

3) `Issue: Permission Denied?:`  
- try this command (chmod +x cameraphish.py), then run script.  

4) `Issue: Python3 or pip not found?:`  
- read the requirements.txt file, (cat requirements.txt) or (gedit requirements.txt).  

5) `Issue: No images are being captured?:`  
- Means The victim does not give camera permission, nothing to do with this , try someone else.  

6) `Issue: IPv6 instead of IPv4 in logs?:`  
- it will show ipv6 (2001:0db8:85a3:0000:0000:8a2e:0370:7334) if there is no ipv4(192.168.1.100) avalible.  

## 🛠️MODIFICATION 

YOU CAN USE CUSTOM TEMPLATES, CREATE UR TEMPLATE AND LINK WITH THE BACKEND AS IN PRE BUILD SCRIPTS  
THEN MOVE IT TO THE TEMPLATES DIRECTORY AND EDIT PYTHON SCRIPT TO ADD UR TEMPLATE AS 11 , 12 .....
OR
IF U WANT TO MODIFY OR USE THE SCRIPT IN UR PROJECTs , CONSIDER GIVING CREDITS !  

## 📂Example OutPut

	└─$ python3 cameraphish.py  

	[🎭] Choose a phishing template:  
	[1] Exclusive Offer  
	[2] Breaking News  
	[3] Scholarship Application  
	[4] Celebrity Video Call  
	[5] Netflix Free Subscription  
	[6] E Commerce Order  
	[7] Birthday Wish  
	[8] Online Meeting  
	[9] Youtube Live  
	[10] Eid Mubarak  

	[➤] Enter your choice (1 to 10): 4  

	✅ Selected Template: Celebrity Video Call  

	[🔄] Starting Cloudflare Tunnel...  

	==========================================================================================  
	💀 Phishing Link: https://secure-video-invite.trycloudflare.com  
	==========================================================================================  

	[🚀] Starting Flask server...  

	[X] Press CTRL + C To Exit....  

	[📸] Image captured from **39.56.160.226** - Saved as `captured_images/39.56.160.226/2025-03-17_18-03-53.png`  
	[📸] Image captured from **39.56.160.226** - Saved as `captured_images/39.56.160.226/2025-03-17_18-03-55.png`  


# ⚠️Disclaimer !
This tool is intended for ethical and educational use only.  
Do not use it for illegal activities. The author is not responsible for any misuse.  
This script is intended for educational purposes and authorized testing only.  
Unauthorized use of this script is illegal and unethical.  
Ensure you have explicit permission before testing any system.  
- Obtain explicit permission before testing any system.  
- Adhere to all applicable laws and regulations.  
- Respect user privacy and data.  
- By using this script, you agree to take full responsibility for your actions.  
