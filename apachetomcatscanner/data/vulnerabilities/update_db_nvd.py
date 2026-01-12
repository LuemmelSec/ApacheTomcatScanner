#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : update_db_nvd.py
# Author             : Modified for NVD API
# Date created       : Jan 2026

import datetime
import glob
import json
import os
import re
import time

import requests

# NVD API configuration
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {
    'User-Agent': 'ApacheTomcatScanner/3.8.2',
    'Accept': 'application/json'
}

def get_apache_releases():
    """Get release versions from Apache archive"""
    dates_releases = {}
    releases_dates = {}
    
    for major_version in [8, 9, 10, 11]:  # Focus on recent versions
        base_url = f"https://archive.apache.org/dist/tomcat/tomcat-{major_version}/"
        print(f"[*] Fetching versions for Tomcat {major_version}...")
        try:
            r = requests.get(base_url, timeout=30)
            matched = re.findall(
                b"((<a href=[^>]+>[^<]+</a>)[ \t\n]+([0-9]{4}-[0-9]{2}-[0-9]{2}[ \t\n]+[0-9]{2}:[0-9]{2}(:[0-9]{2})?))",
                r.content,
            )
            for _, a_tag, date_str, _ in matched:
                href_match = re.search(b'href="([^"]+)"', a_tag)
                if href_match:
                    href = href_match.group(1).decode('utf-8')
                    if href.endswith("/"):
                        version_match = re.search(r"([0-9]+\.[0-9]+\.[0-9]+(-M[0-9]+)?)", href)
                        if version_match:
                            version = version_match.group(1)
                            try:
                                release_date = datetime.datetime.strptime(
                                    date_str.decode("utf-8"), "%Y-%m-%d %H:%M"
                                )
                                release_date_ts = int(release_date.timestamp())
                                
                                if release_date_ts not in dates_releases:
                                    dates_releases[release_date_ts] = []
                                dates_releases[release_date_ts].append(version)
                                
                                if version not in releases_dates:
                                    releases_dates[version] = []
                                releases_dates[version].append(release_date_ts)
                            except (ValueError, UnicodeDecodeError) as e:
                                # Skip entries with unparsable or malformed dates, but continue processing others.
                                print(f"   [!] Skipping release with invalid date format: {e}")
        except Exception as e:
            print(f"   [!] Error fetching versions: {e}")
        time.sleep(0.5)
    
    return dates_releases, releases_dates


def get_cves_from_nvd(year=None):
    """Fetch CVEs for Apache Tomcat from NVD"""
    if year:
        print(f"[*] Fetching CVEs from NVD for year {year}...")
    else:
        print(f"[*] Fetching all CVEs from NVD...")
    cves = {}
    
    # Search for Apache Tomcat CVEs - API 2.0 doesn't support date filters with keywordSearch
    # We'll fetch all and filter by year ourselves
    params = {
        'keywordSearch': 'Apache Tomcat',
        'resultsPerPage': 100
    }
    
    start_index = 0
    total_fetched = 0
    while True:
        params['startIndex'] = start_index
        print(f"   [>] Fetching results starting at index {start_index}...")
        
        try:
            r = requests.get(NVD_API_BASE, params=params, headers=HEADERS, timeout=60)
            
            if r.status_code == 403:
                print("   [!] Rate limited by NVD. Waiting 30 seconds...")
                time.sleep(30)
                continue
            elif r.status_code != 200:
                print(f"   [!] Error: HTTP {r.status_code}")
                print(f"   [!] Response: {r.text[:200]}")
                break
            
            data = r.json()
            total_results = data.get('totalResults', 0)
            vulnerabilities = data.get('vulnerabilities', [])
            
            if not vulnerabilities:
                break
            
            for vuln_item in vulnerabilities:
                cve_data = vuln_item.get('cve', {})
                cve_id = cve_data.get('id', '')
                
                # Extract published date to filter by year if needed
                published = cve_data.get('published', '')
                cve_year = int(published[:4]) if published else 0
                
                # Skip if year filter is set and doesn't match
                if year and cve_year != year:
                    continue
                
                # Check if it's actually Tomcat-related
                description_text = ''
                descriptions = cve_data.get('descriptions', [])
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description_text = desc.get('value', '').lower()
                        break
                
                if 'tomcat' not in description_text:
                    # Also check CPE configurations
                    config_str = str(cve_data.get('configurations', {})).lower()
                    if 'tomcat' not in config_str:
                        continue
                
                print(f"   [>] Processing {cve_id} (year {cve_year})")
                
                # Extract description
                descriptions = cve_data.get('descriptions', [])
                description = ''
                for desc in descriptions:
                    if desc.get('lang') == 'en':
                        description = desc.get('value', '')
                        break
                
                # Extract CVSS score
                metrics = cve_data.get('metrics', {})
                cvss_score = "0.0"
                cvss_vector = ""
                
                # Try CVSS v3.1 first, then v3.0, then v2.0
                for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if version in metrics and metrics[version]:
                        cvss_data = metrics[version][0].get('cvssData', {})
                        cvss_score = str(cvss_data.get('baseScore', '0.0'))
                        cvss_vector = cvss_data.get('vectorString', '')
                        break
                
                # Determine criticity
                risk_levels = ["None", "Low", "Medium", "High", "Critical"]
                criticity = "None"
                try:
                    score_float = float(cvss_score)
                    if score_float == 0:
                        criticity = risk_levels[0]
                    elif 0 < score_float < 4:
                        criticity = risk_levels[1]
                    elif 4 <= score_float < 7:
                        criticity = risk_levels[2]
                    elif 7 <= score_float < 9:
                        criticity = risk_levels[3]
                    elif 9 <= score_float <= 10:
                        criticity = risk_levels[4]
                except Exception:
                    pass
                
                # Extract affected versions from CPE configurations
                affected_versions = []
                version_ranges = []  # Store ranges to expand later
                configurations = cve_data.get('configurations', [])
                for config in configurations:
                    for node in config.get('nodes', []):
                        for cpe_match in node.get('cpeMatch', []):
                            if cpe_match.get('vulnerable', False):
                                criteria = cpe_match.get('criteria', '')
                                if 'apache:tomcat' in criteria:
                                    # Parse version from CPE
                                    cpe_parts = criteria.split(':')
                                    if len(cpe_parts) >= 6:
                                        version = cpe_parts[5]
                                        
                                        # Check for version ranges
                                        version_start = cpe_match.get('versionStartIncluding') or cpe_match.get('versionStartExcluding')
                                        version_end = cpe_match.get('versionEndIncluding') or cpe_match.get('versionEndExcluding')
                                        
                                        if version_start or version_end:
                                            # This is a version range - store it for later expansion
                                            version_ranges.append({
                                                'start': version_start,
                                                'end': version_end,
                                                'start_inclusive': bool(cpe_match.get('versionStartIncluding')),
                                                'end_inclusive': bool(cpe_match.get('versionEndIncluding'))
                                            })
                                        elif version not in ['*', '-']:
                                            # Direct version match
                                            update = ""
                                            if '-' in version:
                                                version_parts = version.split('-', 1)
                                                version = version_parts[0]
                                                update = version_parts[1]
                                            
                                            affected_versions.append({
                                                "tag": version + ("-" + update if update else ""),
                                                "version": version,
                                                "language": "*",
                                                "update": update if update else "*",
                                                "edition": "*"
                                            })
                
                # Expand version ranges using our version database
                def parse_version_tuple(v):
                    """Parse version string into comparable tuple"""
                    parts = v.replace('-M', '.').replace('-m', '.').split('.')
                    result = []
                    for p in parts[:4]:  # major.minor.patch.milestone
                        try:
                            result.append(int(p))
                        except (ValueError, AttributeError):
                            result.append(0)
                    while len(result) < 4:
                        result.append(0)
                    return tuple(result)
                
                for vrange in version_ranges:
                    if vrange['start'] and vrange['end']:
                        try:
                            start_tuple = parse_version_tuple(vrange['start'])
                            end_tuple = parse_version_tuple(vrange['end'])
                            
                            # Find matching versions in our releases database
                            for version_tag in releases_dates.keys():
                                version_tuple = parse_version_tuple(version_tag)
                                
                                # Check if version is in range
                                in_range = start_tuple <= version_tuple <= end_tuple
                                
                                if in_range:
                                    update = ""
                                    ver = version_tag
                                    if '-' in version_tag:
                                        parts = version_tag.split('-', 1)
                                        ver = parts[0]
                                        update = parts[1]
                                    
                                    affected_versions.append({
                                        "tag": version_tag,
                                        "version": ver,
                                        "language": "*",
                                        "update": update if update else "*",
                                        "edition": "*"
                                    })
                        except Exception as e:
                            # If parsing fails, skip this range
                            pass
                
                # Remove duplicates
                unique_versions = []
                seen_tags = set()
                for av in affected_versions:
                    if av["tag"] not in seen_tags:
                        unique_versions.append(av)
                        seen_tags.add(av["tag"])
                
                # Store CVE
                cves[cve_id] = {
                    "cve": {
                        "name": "",
                        "id": cve_id,
                        "year": int(cve_id.split("-")[1]),
                        "vuln_type": "",
                        "publish_date": cve_data.get('published', '')[:10],
                        "update_date": cve_data.get('lastModified', '')[:10]
                    },
                    "cvss": {
                        "score": cvss_score,
                        "criticity": criticity,
                        "gained_access_level": "None",
                        "access": "???",
                        "complexity": "???",
                        "confidentiality": "None",
                        "integrity": "None",
                        "availability": "None"
                    },
                    "affected_versions": unique_versions,
                    "references": [
                        f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    ] + [ref.get('url') for ref in cve_data.get('references', [])],
                    "description": description
                }
                
                # Save immediately to avoid losing progress
                save_path = f"./{cves[cve_id]['cve']['year']}/{cve_id}.json"
                os.makedirs(os.path.dirname(save_path), exist_ok=True)
                with open(save_path, "w") as f:
                    f.write(json.dumps(cves[cve_id], indent=4))
            
            # Check if there are more results
            if start_index + len(vulnerabilities) >= total_results:
                break
            
            start_index += len(vulnerabilities)
            total_fetched += len(vulnerabilities)
            
            # Show progress
            if year:
                print(f"   [*] Progress: {total_fetched}/{total_results} CVEs checked, {len(cves)} Tomcat CVEs found for year {year}")
            
            # Rate limiting: NVD allows 5 requests per 30 seconds without API key
            time.sleep(7)
            
        except Exception as e:
            print(f"   [!] Error: {e}")
            break
    
    return cves


if __name__ == "__main__":
    print("[*] Starting CVE database update using NVD API...")
    print("[!] Note: This will be slow due to NVD rate limiting (5 requests per 30 seconds)")
    print("[!] Consider getting an NVD API key for faster updates: https://nvd.nist.gov/developers/request-an-api-key")
    print()
    
    # Load existing CVEs
    CVES = {}
    if os.path.exists("./"):
        print("[*] Loading existing CVE database...")
        for file in glob.glob("./*/*.json"):
            try:
                with open(file, "r") as f:
                    data = json.loads(f.read())
                CVES[data["cve"]["id"]] = data
            except Exception as e:
                print(f"[!] Warning: Could not load existing CVE file {file}: {e}")
        print(f"[+] Loaded {len(CVES)} existing CVEs")
    
    # Get version information
    dates_releases, releases_dates = get_apache_releases()
    
    # Fetch ALL CVEs from NVD at once (more efficient than year-by-year)
    print("[*] Fetching all Apache Tomcat CVEs from NVD...")
    print("[!] This will take a while due to rate limiting...")
    print("[!] CVEs are saved immediately, so you can interrupt and resume anytime")
    all_cves = get_cves_from_nvd(year=None)
    
    print(f"[+] Fetch complete! Total CVEs in database: {len(all_cves)}")
    
    # Save metadata about the update
    metadata = {
        "last_update": datetime.datetime.now().isoformat(),
        "total_cves": len(all_cves),
        "script_version": "NVD API v2.0"
    }
    
    try:
        metadata_file = "./db_metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"[+] Saved update metadata to {metadata_file}")
    except Exception as e:
        print(f"[!] Warning: Could not save metadata: {e}")
    
    print("[+] Done!")
