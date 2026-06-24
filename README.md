<div align="center">

# 🌍 Microsoft Sentinel – GeoIP Watchlist & Global Attack Map

### Real-World RDP Attack Data Collection, Threat Intelligence Enrichment & Geospatial Visualisation

![Domain](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-blue?style=for-the-badge)
![Type](https://img.shields.io/badge/Type-Threat%20Intelligence%20%26%20Visualisation-purple?style=for-the-badge)
![Data](https://img.shields.io/badge/Data-Real%20World%20Attack%20Traffic-red?style=for-the-badge)

<img src="https://img.shields.io/badge/Watchlist-GeoIP%20Database-blue?style=flat-square" />
<img src="https://img.shields.io/badge/Failed%20Logins-4%2C270%2B-red?style=flat-square" />
<img src="https://img.shields.io/badge/Top%20Origin-Hanoi%20Vietnam%20808-orange?style=flat-square" />
<img src="https://img.shields.io/badge/KQL-ipv4__lookup()-green?style=flat-square" />
<img src="https://img.shields.io/badge/Workbook-Heat%20Map%20greenRed-critical?style=flat-square" />
<img src="https://img.shields.io/badge/Exposure-2%20Days%20Honeypot-yellow?style=flat-square" />

---

**Prepared by:** Bikash Raya
**Project Type:** Threat Intelligence Lab — GeoIP Enrichment, Watchlist & Geospatial Attack Visualisation

> **This is Phase 2 of the [https://github.com/Bikash-Raya/Sentinel-Defender-XDR-SOC-Incident-Response-lab)**
> The same infrastructure was reused — no new VMs were created.

</div>

---

## 📁 Repository Structure

| File | Description |
| --- | --- |
| [Sentinel_GeoIP_Watchlist_Attack_Map_Lab Report](./Sentinel_GeoIP_Watchlist_Attack_Map_Lab.pdf) | Complete lab report with all screenshots embedded |
| README.md | Project overview |

---

## 📋 Overview

After completing the **Hydra RDP Brute Force Incident Response lab**, Web01 (Windows Server 2022) was **intentionally left exposed** to the internet for approximately **2 days** with:

* ❌ NSG inbound rule: **Any/Any/* Allow** (still active)
* ❌ Windows Defender Firewall: **Disabled** (still off)
* ✅ Sentinel collecting all Windows Security Events via AMA

This deliberate exposure allowed **real-world threat actors from around the globe** to discover and attack the exposed RDP port, generating over **4,270 genuine failed login events (Event ID 4625)** from countries including Vietnam, United Kingdom, United States, and more.

These real attack logs were then used to:
* 📌 Create a **GeoIP Watchlist** in Microsoft Sentinel
* 🗺️ Build a **custom Workbook** with KQL + ipv4_lookup() to enrich attack IPs with geographic coordinates
* 🔴 Render a **global heat map** showing the origin of every RDP attack attempt in real time

---

## 🛠️ Technologies Used

* Microsoft Sentinel (Watchlist + Workbooks)
* Microsoft Defender XDR (security.microsoft.com)
* KQL — ipv4_lookup(), _GetWatchlist(), summarize, project
* GeoIP CSV Database (joshmadakor1 / SecLists)
* Log Analytics Workspace (Bik-SOC-Lab)
* Windows Security Events via AMA
* Azure VM (Web01 — Windows Server 2022)

---

## 🧪 Lab Setup (Reused from Previous Lab)

| Component | Value |
| --- | --- |
| Resource Group | Security-BikSecOps (Australia East) |
| Victim VM | Web01 -- Windows Server 2022 (Public IP: 20.5.48.127) |
| NSG Inbound Rule | Any/Any/* Allow -- left open intentionally |
| Windows Firewall | Disabled on Web01 -- left off intentionally |
| Log Analytics Workspace | Bik-SOC-Lab |
| Microsoft Sentinel | Already enabled from previous lab |
| Data Connector | Windows Security Events via AMA -- still active |
| DCR | SecurityEventsforAzureVM -- All Events -- still running |
| Exposure Duration | ~2 days |

> No new infrastructure was deployed. Web01 acted as a **real-world honeypot** simply by remaining publicly accessible.

---

## 🌐 Lab Architecture

```
[Internet -- Global Threat Actors]
  Vietnam | UK | USA | Europe | Asia
         │
         │  Automated RDP Scanning & Brute Force
         │  Port 3389 (RDP) -- NSG Any/Any/* Allow
         ▼
[Web01 -- Windows Server 2022]
  Public IP: 20.5.48.127
  Firewall: OFF | NSG: Open
  Real attack traffic collected over ~2 days
         │
         │  Event ID 4625 (Failed RDP Login)
         │  Windows Security Events via AMA + DCR
         ▼
[Log Analytics Workspace -- Bik-SOC-Lab]
         │
         ▼
[Microsoft Sentinel]
  ├── Watchlist: geoip (GeoIP CSV -- network/lat/lon/city/country)
  │
  └── Workbook: Windows Server VM Attack -- MAP
         KQL: SecurityEvent (4625) + ipv4_lookup(geoip)
         Visualisation: Global Heat Map (greenRed palette)
         Result: 4,270+ attacks plotted on world map
```

---

## 🔬 Lab Phases

### Phase 1 — Create GeoIP Watchlist

Downloaded the GeoIP CSV database:

```
https://github.com/Bikash-Raya/Sentinel-Defender-XDR-SOC-Incident-Response-lab/blob/main/geoip-summarized.csv
```

Uploaded to **Microsoft Sentinel Watchlist** via Defender XDR portal:

| Setting | Value |
| --- | --- |
| Watchlist Name | geoip |
| Alias | geoip |
| Source Type | Local file |
| File Type | CSV file with header |
| Search Key | network |
| Columns | network, latitude, longitude, cityname, countryname |

---

### Phase 2 — Build Workbook with Global Attack Map

Created a new Sentinel Workbook and added the following **KQL query** via Advanced Editor:

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent;
WindowsEvents
| where EventID == 4625
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize FailureCount = count()
    by IpAddress, latitude, longitude, cityname, countryname
| project
    FailureCount,
    AttackerIp        = IpAddress,
    latitude,
    longitude,
    city              = cityname,
    country           = countryname,
    friendly_location = strcat(cityname, " (", countryname, ")")
```

**Map configuration:**

```json
"visualization": "map",
"mapSettings": {
  "locInfo": "LatLong",
  "latitude": "latitude",
  "longitude": "longitude",
  "sizeSettings": "FailureCount",
  "sizeAggregation": "Sum",
  "opacity": 0.8,
  "labelSettings": "friendly_location",
  "legendMetric": "FailureCount",
  "itemColorSettings": {
    "nodeColorField": "FailureCount",
    "type": "heatmap",
    "heatmapPalette": "greenRed"
  }
}
```

---

## 📊 Results — Global Attack Origins

After ~2 days of exposure, **4,270+ failed RDP login attempts** were recorded from the following locations:

| Location | Failed Logins (4625) | Region |
| --- | --- | --- |
| Hanoi, Vietnam | 808 | Asia |
| Southampton, United Kingdom | 795 | Europe |
| London, United Kingdom | 681 | Europe |
| Birmingham, United Kingdom | 292 | Europe |
| Trenton, United States | 258 | North America |
| Newton Aycliffe, United Kingdom | 154 | Europe |
| United States (unspecified) | 144 | North America |
| Winslow, United Kingdom | 123 | Europe |
| Other / Unresolved IPs | 4,270+ | Global |

**Total Security Events ingested:** 424,000+ | **SecurityAlert:** 1,540 | **Incidents:** 40

> The concentration of attacks from the UK reflects VPN exit nodes and proxy infrastructure commonly used by automated scanning botnets. Hanoi (Vietnam) is a known global source of RDP scanning activity.

---

## 💡 Key Concepts Demonstrated

**Watchlist-Based Threat Intelligence Enrichment**
The `_GetWatchlist("geoip")` function in KQL retrieves the uploaded GeoIP database at query time, enabling dynamic enrichment of raw IP addresses with geographic context — no preprocessing required.

**ipv4_lookup() — CIDR Range Matching**
The `ipv4_lookup()` plugin matches each attacker IP against the GeoIP watchlist's CIDR network ranges, returning the correct geographic record even when the exact IP is not listed.

**Real-World Honeypot Effect**
Leaving Web01 exposed for 2 days produced genuine attack traffic equivalent to a real honeypot deployment — demonstrating the volume and diversity of automated internet scanning that any exposed cloud VM attracts.

**Geospatial Visualisation in SOC Dashboards**
The greenRed heat map workbook provides an executive-level view of the organisation's threat landscape — green = low activity, red = high attack concentration. This type of dashboard is standard in enterprise SOC environments.

---

## 🎯 Skills Demonstrated

* Microsoft Sentinel Watchlist Creation & Management
* GeoIP Threat Intelligence Integration
* KQL Advanced Queries — ipv4_lookup(), _GetWatchlist(), summarize, project
* Sentinel Workbook Development (Advanced Editor / JSON)
* Geospatial Attack Visualisation (Heat Map)
* Real-World Attack Data Collection (Honeypot)
* Security Event Log Analysis (Event ID 4625)
* Threat Intelligence Enrichment Techniques
* SOC Dashboard Building
* Microsoft Defender XDR Portal Navigation

---

## 🔗 Related Project

> This lab is a continuation of:
> **[Microsoft Sentinel & Defender XDR — SOC Incident Response Lab](https://github.com/Bikash-Raya/Sentinel-Defender-XDR-SOC-Incident-Response-lab)**
> *(Hydra RDP Brute Force Attack, Analytics Rule, Incident ID 18 — same infrastructure)*

---

## 🎯 Key Takeaway

> This lab demonstrates hands-on experience with Microsoft Sentinel threat intelligence enrichment — creating a GeoIP watchlist, building a custom KQL workbook using ipv4_lookup() to enrich real-world attack data, and visualising global attack origins on a live heat map. By intentionally leaving an Azure VM exposed for 2 days, over 4,270 real failed RDP login attempts were captured from threat actors across Vietnam, UK, USA, and Europe — demonstrating exactly what SOC analysts see monitoring publicly exposed cloud infrastructure.

---

## 🔗 Connect With Me

<div align="center">

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/bikash-raya/)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=for-the-badge&logo=github)](https://github.com/Bikash-Raya)

</div>

---

<div align="center">

⭐ If you find this project useful, feel free to star the repository ⭐

</div>
