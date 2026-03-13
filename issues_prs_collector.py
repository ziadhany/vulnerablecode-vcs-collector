#
# Copyright (c) nexB Inc. and others. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os
import re
import sys
from abc import abstractmethod
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import gitlab
from aboutcode.pipeline import BasePipeline, LoopProgress
from github import Github

github_token = os.environ.get("GITHUB_TOKEN")
gitlab_token = os.environ.get("GITLAB_TOKEN")


class VCSCollector(BasePipeline):
    """
    Pipeline to collect GitHub/GitLab issues and PRs related to vulnerabilities.
    """

    vcs_url: str
    CVE_PATTERN = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)
    SUPPORTED_IDENTIFIERS = ["CVE-"]

    collected_items: dict = {}

    def __init__(self, vcs_url: str, *args, **kwargs):
        self.vcs_url = vcs_url
        super().__init__(*args, **kwargs)

    @classmethod
    def steps(cls):
        return (
            cls.configure_target,
            cls.fetch_entries,
            cls.collect_items,
            cls.store_items,
        )

    def configure_target(self):
        parsed_url = urlparse(self.vcs_url)
        parts = parsed_url.path.strip("/").split("/")
        if len(parts) < 2:
            raise ValueError(f"Invalid URL: {self.vcs_url}")

        self.repo_name = f"{parts[0]}/{parts[1]}"

    def log(self, message):
        now_local = datetime.now(timezone.utc).astimezone()
        timestamp = now_local.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        message = f"{timestamp} {message}"
        print(message)

    @abstractmethod
    def fetch_entries(self):
        raise NotImplementedError

    @abstractmethod
    def collect_items(self):
        raise NotImplementedError

    def store_items(self):
        self.log("Storing collected fix commit results.")
        repo_name = self.vcs_url.replace("https://github.com", "")
        path = Path(f"data/issues-prs/{repo_name}.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            serialized_data = {
                cve: {i_type: list(set(urls)) for i_type, urls in type_data.items()}
                for cve, type_data in self.collected_items.items()
            }

            json.dump(serialized_data, f, indent=2)
        return


class GitLabCollector(VCSCollector):
    def fetch_entries(self):
        """Fetch GitLab Data Entries"""
        gl = gitlab.Gitlab("https://gitlab.com/", private_token=gitlab_token)
        project = gl.projects.get(self.repo_name)
        base_query = " ".join(self.SUPPORTED_IDENTIFIERS)
        self.issues = project.search(scope="issues", search=base_query)
        self.prs = project.search(scope="merge_requests", search=base_query)

    def collect_items(self):
        self.collected_items = defaultdict(lambda: defaultdict(set))
        for i_type, items in [("Issue", self.issues), ("PR", self.prs)]:
            for item in items:
                title = item.get("title") or ""
                description = item.get("description") or ""
                matches = self.CVE_PATTERN.findall(title + " " + description)
                for match in matches:
                    cve_id = match.upper()
                    url = item.get("web_url")
                    if not url:
                        continue
                    self.collected_items[cve_id][i_type].add(url)


class GitHubCollector(VCSCollector):
    def fetch_entries(self):
        """Fetch GitHub Data Entries"""
        g = Github(login_or_token=github_token)
        base_query = (
            f"repo:{self.repo_name} ({' OR '.join(self.SUPPORTED_IDENTIFIERS)})"
        )
        self.issues = g.search_issues(f"{base_query} is:issue")
        self.prs = g.search_issues(f"{base_query} is:pr")

    def collect_items(self):
        self.collected_items = defaultdict(lambda: defaultdict(set))
        for i_type, items in [("Issues", self.issues), ("PRs", self.prs)]:
            for item in items:
                matches = self.CVE_PATTERN.findall(item.title + " " + (item.body or ""))
                for match in matches:
                    cve_id = match.upper()
                    self.collected_items[cve_id][i_type].add(item.html_url)


if __name__ == "__main__":
    with open("config/issues_prs_targets.json") as f:
        vcs_urls = json.load(f)

    progress = LoopProgress(
        total_iterations=len(vcs_urls),
        logger=print,
    )
    for vcs_url in progress.iter(vcs_urls):
        if vcs_url.startswith("https://gitlab.com"):
            collector = GitLabCollector(vcs_url=vcs_url)
        elif vcs_url.startswith("https://github.com"):
            collector = GitHubCollector(vcs_url=vcs_url)
        else:
            print(f"Unsupported VCS URL: {vcs_url}")
            continue

        status_code, error_msg = collector.execute()
        print(error_msg)

    sys.exit(0)
