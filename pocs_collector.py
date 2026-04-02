#
# Copyright (c) nexB Inc. and others. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import sys
from datetime import datetime, timezone
from pathlib import Path

from aboutcode.pipeline import BasePipeline
from dotenv import load_dotenv
import os
import json
from github import Github, Auth
from fetchcode.vcs import fetch_via_vcs

load_dotenv()

BATCH_SIZE = 1000

class PocsCollector(BasePipeline):
    @classmethod
    def steps(cls):
        return (
            cls.collect_items,
        )

    def get_start_index(self):
        with open("config/checkpoints.json", "r") as f:
            return json.load(f).get("index", 0)

    def save_index(self, index):
        with open("config/checkpoints.json", "w") as f:
            json.dump({"index": index}, f)

    def log(self, message):
        now_local = datetime.now(timezone.utc).astimezone()
        timestamp = now_local.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        message = f"{timestamp} {message}"
        print(message)

    def get_cve_list(self):
        vcs_response = fetch_via_vcs("git+https://github.com/CVEProject/cvelistV5")
        cves = set()
        for file_path in Path(vcs_response.dest_dir).glob("**/*.json"):
            if file_path.is_file() and file_path.name.startswith("CVE-"):
                cves.add(file_path.stem)
        return sorted(cves)

    def get_pocs_repo_urls(self, cve_id):
        """Searches GitHub and returns a list of POCS URLs"""
        query = (
            f'{cve_id} in:name,description '
            f'fork:false '
        )
        results = github.search_repositories(query=query)
        pocs_urls = set()
        count = 0

        if results.totalCount == 0:
            return []

        for item in results:
            if not (cve_id in item.description or cve_id in item.name):
                continue

            pocs_urls.add(item.html_url)
            count += 1
        return sorted(list(pocs_urls))

    def collect_items(self):
        total_cves = self.get_cve_list()
        start_index = self.get_start_index()
        end_index = start_index + BATCH_SIZE
        self.log(f"Batch Started from index {start_index} to {end_index}")
        for cve_id in total_cves[start_index:end_index]:
            pocs_repo_urls = self.get_pocs_repo_urls(cve_id)
            if not pocs_repo_urls:
                continue

            parts = cve_id.split("-")
            path = os.path.join("data/pocs", parts[1], f"{cve_id}.json")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            data = {
                "cve_id": cve_id,
                "repositories": list(pocs_repo_urls),
                "count": len(pocs_repo_urls),
            }

            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

        next_index = end_index if end_index < len(total_cves) else 0
        self.save_index(next_index)
        self.log(f"Batch complete. Saved next index: {next_index}")

if __name__ == "__main__":
    github_token = os.getenv("GH_API_TOKEN")
    if not github_token:
        raise ValueError("GH_API_TOKEN environment variable not set properly")

    auth = Auth.Token(github_token)
    github = Github(auth=auth)
    collector = PocsCollector()
    status_code, error_msg = collector.execute()
    print(error_msg)
    sys.exit(0)