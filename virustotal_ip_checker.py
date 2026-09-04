import requests
import csv
import time
import ipaddress
import os
import sys

# ============================================================
# VIRUSTOTAL IP ADDRESS CHECKER
# ============================================================
#
# INPUT:
#     ips.txt
#
# OUTPUT:
#     virustotal_results.csv
#
# EXAMPLE:
#
#     192.168.29.134    -> 0/91
#     8.8.8.8           -> 0/91
#     185.220.101.1     -> 5/91
#
# The script:
#   - Reads IPs from ips.txt
#   - Removes duplicates
#   - Validates IP addresses
#   - Checks IPv4 and IPv6
#   - DOES NOT skip private IPs
#   - Queries VirusTotal
#   - Produces the actual detection ratio
#   - Saves results after EVERY IP
#   - Can resume after interruption
#   - Handles VirusTotal rate limits
#   - Saves errors separately from real VT scores
#
# ============================================================


# ============================================================
# CONFIGURATION
# ============================================================

# PUT YOUR VIRUSTOTAL API KEY HERE
API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"

INPUT_FILE = "ips.txt"

OUTPUT_FILE = "virustotal_results.csv"

# VirusTotal Public API:
# 4 requests per minute
#
# 16 seconds between requests gives approximately
# 3.75 requests per minute.
REQUEST_DELAY = 16

API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"


# ============================================================
# CSV COLUMNS
# ============================================================

CSV_COLUMNS = [
    "IP",
    "VirusTotal Score",
    "Malicious",
    "Suspicious",
    "Harmless",
    "Undetected",
    "Country",
    "ASN",
    "AS Owner",
    "Reputation",
    "Status"
]


# ============================================================
# CHECK API KEY
# ============================================================

if not API_KEY or len(API_KEY.strip()) != 64:

    print()
    print("=" * 60)
    print("ERROR: VirusTotal API key is missing or invalid.")
    print("=" * 60)
    print()
    print("Please make sure API_KEY contains a valid 64-character VirusTotal key.")
    print()
    sys.exit(1)

# ============================================================
# VALIDATE IP
# ============================================================

def validate_ip(ip):

    try:
        ipaddress.ip_address(ip)
        return True

    except ValueError:
        return False


# ============================================================
# LOAD IPs
# ============================================================

def load_ips():

    if not os.path.exists(INPUT_FILE):

        print()
        print(f"ERROR: {INPUT_FILE} was not found.")
        print()
        print("Create ips.txt in the same folder as this script.")
        print()

        sys.exit(1)

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        lines = file.readlines()

    cleaned_ips = []

    for line in lines:

        ip = line.strip()

        # Ignore blank lines
        if not ip:
            continue

        # Remove duplicate IPs
        if ip not in cleaned_ips:
            cleaned_ips.append(ip)

    return cleaned_ips


# ============================================================
# LOAD PREVIOUS RESULTS
# ============================================================

def load_previous_results():

    previous_results = {}

    if not os.path.exists(OUTPUT_FILE):

        return previous_results

    try:

        with open(
            OUTPUT_FILE,
            "r",
            newline="",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)

            for row in reader:

                ip = row.get("IP")

                if ip:
                    previous_results[ip] = row

    except Exception as error:

        print(
            f"\nWarning: Could not read previous results: {error}"
        )

    return previous_results


# ============================================================
# SAVE RESULTS
# ============================================================

def save_results(results):

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=CSV_COLUMNS
        )

        writer.writeheader()

        writer.writerows(results)


# ============================================================
# CREATE ERROR RESULT
# ============================================================

def create_result(
    ip,
    score="",
    malicious="",
    suspicious="",
    harmless="",
    undetected="",
    country="",
    asn="",
    as_owner="",
    reputation="",
    status=""
):

    return {

        "IP": ip,

        "VirusTotal Score": score,

        "Malicious": malicious,

        "Suspicious": suspicious,

        "Harmless": harmless,

        "Undetected": undetected,

        "Country": country,

        "ASN": asn,

        "AS Owner": as_owner,

        "Reputation": reputation,

        "Status": status
    }


# ============================================================
# CHECK VIRUSTOTAL
# ============================================================

def check_virustotal(ip):

    url = API_URL.format(ip)

    headers = {

        "x-apikey": API_KEY,

        "Accept": "application/json"
    }

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=30
        )

    except requests.exceptions.Timeout:

        return create_result(
            ip,
            score="",
            status="NETWORK TIMEOUT"
        )

    except requests.exceptions.RequestException as error:

        return create_result(
            ip,
            score="",
            status=f"NETWORK ERROR: {error}"
        )


    # ========================================================
    # SUCCESS
    # ========================================================

    if response.status_code == 200:

        try:

            json_data = response.json()

        except ValueError:

            return create_result(
                ip,
                score="",
                status="INVALID JSON RESPONSE"
            )


        attributes = (
            json_data
            .get("data", {})
            .get("attributes", {})
        )


        # ====================================================
        # ANALYSIS STATISTICS
        # ====================================================

        stats = attributes.get(
            "last_analysis_stats"
        )


        # ----------------------------------------------------
        # NO ANALYSIS STATISTICS
        # ----------------------------------------------------

        if not stats:

            return create_result(
                ip,
                score="NO REPORT",
                status="NO ANALYSIS DATA"
            )


        malicious = stats.get(
            "malicious",
            0
        )

        suspicious = stats.get(
            "suspicious",
            0
        )

        harmless = stats.get(
            "harmless",
            0
        )

        undetected = stats.get(
            "undetected",
            0
        )


        # ====================================================
        # CALCULATE TOTAL
        # ====================================================
        #
        # Example:
        #
        # malicious  = 0
        # suspicious = 0
        # harmless   = 20
        # undetected = 71
        #
        # TOTAL = 91
        #
        # SCORE = 0/91
        #
        # ====================================================

        total = (
            malicious
            + suspicious
            + harmless
            + undetected
        )


        # ====================================================
        # YOUR REQUIRED FORMAT
        # ====================================================

        score = f"{malicious}/{total}"


        # ====================================================
        # ADDITIONAL INFORMATION
        # ====================================================

        country = attributes.get(
            "country",
            ""
        )

        asn = attributes.get(
            "asn",
            ""
        )

        as_owner = attributes.get(
            "as_owner",
            ""
        )

        reputation = attributes.get(
            "reputation",
            ""
        )


        return create_result(

            ip=ip,

            score=score,

            malicious=malicious,

            suspicious=suspicious,

            harmless=harmless,

            undetected=undetected,

            country=country,

            asn=asn,

            as_owner=as_owner,

            reputation=reputation,

            status="SUCCESS"
        )


    # ========================================================
    # RATE LIMIT
    # ========================================================

    elif response.status_code == 429:

        return create_result(
            ip,
            score="",
            status="RATE LIMITED"
        )


    # ========================================================
    # INVALID API KEY
    # ========================================================

    elif response.status_code == 401:

        return create_result(
            ip,
            score="",
            status="INVALID API KEY"
        )


    # ========================================================
    # FORBIDDEN
    # ========================================================

    elif response.status_code == 403:

        return create_result(
            ip,
            score="",
            status="FORBIDDEN / API LIMIT"
        )


    # ========================================================
    # IP NOT FOUND
    # ========================================================

    elif response.status_code == 404:

        return create_result(
            ip,
            score="NO REPORT",
            status="IP NOT FOUND"
        )


    # ========================================================
    # OTHER ERROR
    # ========================================================

    else:

        return create_result(
            ip,
            score="",
            status=f"HTTP ERROR {response.status_code}"
        )


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    print()
    print("=" * 60)
    print("        VIRUSTOTAL IP ADDRESS CHECKER")
    print("=" * 60)
    print()


    # ========================================================
    # LOAD IPs
    # ========================================================

    ips = load_ips()


    print(
        f"Unique IP addresses found: {len(ips)}"
    )

    print()


    # ========================================================
    # LOAD PREVIOUS RESULTS
    # ========================================================

    previous_results = load_previous_results()


    if previous_results:

        print(
            f"Previous results found: "
            f"{len(previous_results)}"
        )

        print(
            "Already completed IPs will be skipped."
        )

        print()


    results = []


    # ========================================================
    # PROCESS IPs
    # ========================================================

    for index, ip in enumerate(
        ips,
        start=1
    ):


        # ----------------------------------------------------
        # RESUME SUPPORT
        # ----------------------------------------------------

        if ip in previous_results:

            previous = previous_results[ip]

            # Only skip successful / completed results
            status = previous.get(
                "Status",
                ""
            )

            if status in [
                "SUCCESS",
                "NO ANALYSIS DATA",
                "IP NOT FOUND"
            ]:

                results.append(previous)

                print(
                    f"[{index}/{len(ips)}] "
                    f"{ip} → "
                    f"{previous.get('VirusTotal Score', '')} "
                    f"(already checked)"
                )

                continue


        # ----------------------------------------------------
        # VALIDATE IP
        # ----------------------------------------------------

        if not validate_ip(ip):

            print(
                f"[{index}/{len(ips)}] "
                f"{ip} → INVALID IP"
            )


            result = create_result(

                ip=ip,

                score="",

                status="INVALID IP"
            )


            results.append(result)

            save_results(results)

            continue


        # ----------------------------------------------------
        # CHECK VIRUSTOTAL
        # ----------------------------------------------------

        print(
            f"[{index}/{len(ips)}] "
            f"Checking {ip}...",
            end=" "
        )


        result = check_virustotal(ip)


        results.append(result)


        # ----------------------------------------------------
        # DISPLAY RESULT
        # ----------------------------------------------------

        score = result[
            "VirusTotal Score"
        ]

        status = result[
            "Status"
        ]


        if score:

            print(
                f"→ {score} "
                f"({status})"
            )

        else:

            print(
                f"→ {status}"
            )


        # ----------------------------------------------------
        # SAVE IMMEDIATELY
        # ----------------------------------------------------

        save_results(results)


        # ----------------------------------------------------
        # RATE LIMIT DELAY
        # ----------------------------------------------------

        if index < len(ips):

            print(
                f"    Waiting "
                f"{REQUEST_DELAY} seconds..."
            )

            time.sleep(
                REQUEST_DELAY
            )


    # ========================================================
    # FINISHED
    # ========================================================

    print()
    print("=" * 60)
    print("                    COMPLETE")
    print("=" * 60)
    print()

    print(
        f"Results saved to:"
    )

    print(
        f"    {OUTPUT_FILE}"
    )

    print()


# ============================================================
# START PROGRAM
# ============================================================

if __name__ == "__main__":

    main()