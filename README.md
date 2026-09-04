# VirusTotal IP Reputation Checker for SOC Analysts

An automated Python script designed to assist SOC analysts in triaging large batches of IP addresses using the VirusTotal v3 API. It parses addresses, validates them, queries VirusTotal while respecting public rate limits, and exports analysis ratios, geolocation, and ASN details directly to a CSV spreadsheet.

---

## ⚠️ IMPORTANT: API Quota & Multi-Account Usage

* **Get Your API Key:** You must create a free account on [VirusTotal](https://www.virustotal.com/) to obtain an API key. Once signed up, find your personal API key under your profile settings.
* **Daily Limit:** A free VirusTotal public API account is restricted to **500 requests per day** and **4 requests per minute**.


* **500 IPs Per Account:** Once you check 500 IPs, that specific account's API key will stop returning data for 24 hours.
* **Switching Keys & Workstations:** If you need to scan more than 500 IPs per day, create a separate VirusTotal account to generate a new API key and update the script. To run concurrent batches with separate keys, use a different laptop/machine so the command prompt (CMD) instances run independently without conflicting state or locks.

---

## Prerequisites

* Python 3.8+ installed on your computer.
* A registered VirusTotal account (to get your free API key).
* Python `requests` library installed:


```cmd
pip install requests

```



---

## Step-by-Step Instructions

1. **Get Your API Key:** Create a free account on [VirusTotal](https://www.virustotal.com/). Go to your profile menu in the top-right corner, click on **API Key**, and copy your 64-character key.
2. **Create a Folder:** Create a new folder on your system (e.g., on your Desktop) to hold your project files.
3. **Paste the `.py` File:** Move or download the `virustotal_ip_checker.py` file into this folder.


4. **Add Your API Key Inside `""`:** Open `virustotal_ip_checker.py` in a text editor and locate line 44:


```python
API_KEY = "YOUR_ACTUAL_API_KEY"

```


Paste your 64-character VirusTotal API key inside the double quotation marks (`""`). **Do not delete the quotation marks**, or the script will fail to run.


5. **Create the `ips.txt` File:** In the exact same folder as the script, create a new text file and name it strictly **`ips.txt`**.


* *Note:* You must use the exact name **`ips.txt`** because the script only accepts and looks for this specific file name as input.




6. **Paste IPs in the File:** Open `ips.txt` and paste only your IP addresses—one IP per line. Do not include extra text, commas, or descriptions.


```text
192.168.29.134
8.8.8.8
185.220.101.1

```


7. **Open CMD and Run the Script:**
* Open Command Prompt (`cmd`).
* Navigate to the folder where your files are saved:
```cmd
cd path\to\your\folder

```

* Run the script:
```cmd
python virustotal_ip_checker.py

```


---

## Output

* Results are written line-by-line directly into `virustotal_results.csv` after every query.
* If stopped or interrupted, re-running the script will automatically pick up where it left off and skip already completed IPs.


* If stopped or interrupted, re-running the script will automatically pick up where it left off and skip already completed IPs.
