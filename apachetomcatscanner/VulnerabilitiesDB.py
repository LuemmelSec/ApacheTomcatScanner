#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : VulnerabilitiesDB.py
# Author             : Podalirius (@podalirius_)
# Date created       : 24 Jul 2022

import glob
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta


class VulnerabilitiesDB(object):
    """
    Documentation for class VulnerabilitiesDB
    """

    def __init__(self, config, auto_update_days=30, skip_auto_update=False):
        super(VulnerabilitiesDB, self).__init__()
        self.config = config
        self.cves = {}
        self.versions_to_cves = {}
        self.auto_update_days = auto_update_days
        self.metadata_file = os.path.join(os.path.dirname(__file__), "data", "db_metadata.json")
        
        # Check if database needs updating (unless disabled)
        if not skip_auto_update and self.should_update_database():
            print("[!] CVE database is outdated (last update: %s)" % self.get_last_update_date())
            print("[*] You can update it by running: python apachetomcatscanner/data/update_db_nvd.py")
            response = input("[?] Would you like to update now? This may take several minutes. (y/N): ")
            if response.lower() in ['y', 'yes']:
                self.update_database()
        
        self.load()

    def load(self):
        self.cves = {}
        self.config.debug("Loading CVEs from JSON database ...")

        # Load all CVEs from JSON files
        path_to_json_files = os.path.sep.join(
            [os.path.dirname(__file__), "data", "vulnerabilities", "*", "CVE-*.json"]
        )

        for cve_json_file in glob.glob(path_to_json_files):
            try:
                f = open(cve_json_file, "r")
                cve = json.loads(f.read())
                f.close()
                if "cve" in cve.keys():
                    if "id" in cve["cve"].keys():
                        self.cves[cve["cve"]["id"]] = cve
            except Exception:
                pass
        self.config.debug("Loaded %d CVEs!" % len(self.cves.keys()))

        # Construct reverse lookup database from version to CVEs
        if len(self.cves.keys()) != 0:
            for cve_id, cve_data in self.cves.items():
                for version in cve_data["affected_versions"]:
                    if version["tag"] not in self.versions_to_cves.keys():
                        self.versions_to_cves[version["tag"]] = []
                    self.versions_to_cves[version["tag"]].append(cve_data)

    def get_vulnerabilities_of_version_sorted_by_criticity(
        self, version_tag, colors=False, reverse=False
    ):
        colored_criticity = {
            "None": "\x1b[1;48;2;83;170;51;97m%s\x1b[0m",
            "Low": "\x1b[1;48;2;255;203;13;97m%s\x1b[0m",
            "Medium": "\x1b[1;48;2;249;160;9;97m%s\x1b[0m",
            "High": "\x1b[1;48;2;233;61;3;97m%s\x1b[0m",
            "Critical": "\x1b[1;48;2;45;45;45;97m%s\x1b[0m",
        }
        vulnerabilities = []
        if version_tag in self.versions_to_cves.keys():
            vulnerabilities = self.versions_to_cves[version_tag]
            vulnerabilities = sorted(
                vulnerabilities, key=lambda cve: float(cve["cvss"]["score"]) if cve["cvss"]["score"] else 0, reverse=reverse
            )
            if colors:
                vulnerabilities = [
                    (
                        colored_criticity[vuln["cvss"]["criticity"]]
                        % vuln["cve"]["id"],
                        vuln,
                    )
                    for vuln in vulnerabilities
                ]
        return vulnerabilities

    def get_vulnerabilities_of_version_sorted_by_year(self, version_tag, reverse=False):
        vulnerabilities = []
        if version_tag in self.versions_to_cves.keys():
            vulnerabilities = self.versions_to_cves[version_tag]
            vulnerabilities = sorted(
                vulnerabilities, key=lambda cve: cve["cve"]["year"], reverse=reverse
            )
        return vulnerabilities
    
    def get_last_update_date(self):
        """Get the last update date from metadata file"""
        try:
            if os.path.exists(self.metadata_file):
                with open(self.metadata_file, 'r') as f:
                    metadata = json.load(f)
                    return metadata.get('last_update', 'Never')
        except Exception:
            pass
        return 'Never'
    
    def should_update_database(self):
        """Check if database should be updated based on age"""
        try:
            if not os.path.exists(self.metadata_file):
                return True
            
            with open(self.metadata_file, 'r') as f:
                metadata = json.load(f)
                last_update_str = metadata.get('last_update')
                
                if not last_update_str:
                    return True
                
                last_update = datetime.fromisoformat(last_update_str)
                days_old = (datetime.now() - last_update).days
                
                return days_old >= self.auto_update_days
        except Exception:
            return True
    
    def update_database(self):
        """Run the update script to fetch latest CVEs from NVD"""
        update_script = os.path.join(os.path.dirname(__file__), "data", "update_db_nvd.py")
        
        if not os.path.exists(update_script):
            print("[!] Error: Update script not found at %s" % update_script)
            return False
        
        try:
            print("[*] Starting CVE database update from NVD API...")
            # Run the update script
            result = subprocess.run(
                [sys.executable, update_script],
                capture_output=False,
                text=True,
                cwd=os.path.dirname(update_script)
            )
            
            if result.returncode == 0:
                print("[+] Database update completed successfully!")
                return True
            else:
                print("[!] Database update failed with return code %d" % result.returncode)
                return False
        except Exception as e:
            print("[!] Error during database update: %s" % str(e))
            return False
