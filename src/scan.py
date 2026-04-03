import argparse
import glob
import html as html_mod
import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum

import yaml


class Severity(Enum):
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    UNKNOWN = 4


class Scanner(Enum):
    TRIVY = "trivy"
    GRYPE = "grype"


@dataclass
class Vulnerability:
    pkg_name: str
    vulnerability_id: str
    severity: str
    installed_version: str
    fixed_version: str
    links: list[str] = field(default_factory=list)
    pkg_type: str = ""

    @property
    def is_os_package(self) -> bool:
        return self.pkg_type in {"deb", "rpm", "apk"}

    @property
    def severity_rank(self) -> int:
        return Severity[self.severity].value if self.severity in Severity.__members__ else 99


@dataclass
class ScanConfig:
    show_links: bool = True
    severity_levels: str = "LOW,MEDIUM,HIGH,CRITICAL"
    retries: int = 3
    exclude_patterns: list[str] = field(default_factory=list)
    exclude_regex: str | None = None
    slack_token: str | None = None
    slack_channel: str | None = None
    slack_mention: str | None = None


def _esc(text) -> str:
    return html_mod.escape(str(text))


class ImageScanner(ABC):
    MAX_RETRIES = 3
    RETRY_DELAY = 5

    def __init__(self):
        self.html_files: list[str] = []

    @property
    @abstractmethod
    def label(self) -> str: ...

    @abstractmethod
    def scan_image(self, image: str, config: ScanConfig) -> str | None: ...

    def _register_html(self, image: str) -> str:
        name = f"{image.replace('/', '_').replace(':', '_')}.html"
        path = os.path.join(os.getcwd(), name)
        if path not in self.html_files:
            self.html_files.append(path)
        return path


class TrivyScanner(ImageScanner):
    @property
    def label(self) -> str:
        return "Trivy"

    @staticmethod
    def _process_template(template_path, show_links):
        """Preprocess the HTML template to include/exclude links sections."""
        with open(template_path, "r") as f:
            content = f.read()

        if show_links:
            content = content.replace("{{/* LINKS_ONLY */}}\n", "")
            content = content.replace("{{/* END_LINKS_ONLY */}}\n", "")
            content = content.replace("__TOTAL_COLS__", "6")
        else:
            content = re.sub(
                r"\{\{/\* LINKS_ONLY \*/\}\}\n.*?\{\{/\* END_LINKS_ONLY \*/\}\}\n",
                "",
                content,
                flags=re.DOTALL,
            )
            content = content.replace("__TOTAL_COLS__", "5")

        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".tpl", delete=False)
        tmp.write(content)
        tmp.close()
        return tmp.name

    def scan_image(self, image, config):
        html_file_path = self._register_html(image)

        templates_dir = os.path.join(
            os.path.abspath(os.path.dirname(__file__)), "templates"
        )
        template_path = os.path.join(templates_dir, "html.tpl")
        processed_template = self._process_template(template_path, config.show_links)

        try:
            trivy_cmd = [
                "trivy",
                "image",
                "-q",
                "--severity",
                config.severity_levels,
                "-f",
                "template",
                "--template",
                f"@{processed_template}",
                "-o",
                html_file_path,
                "--scanners",
                "vuln",
                image,
            ]

            retries = 0
            while retries < self.MAX_RETRIES:
                logging.debug("Running command: %s", " ".join(trivy_cmd))
                result = subprocess.run(trivy_cmd, capture_output=True, text=True)

                if result.returncode == 0:
                    logging.info(f"Trivy scan completed for image {image}")
                    return html_file_path
                elif "TOOMANYREQUESTS" in result.stderr:
                    retries += 1
                    logging.warning(
                        f"Rate limit error for image {image}. Retrying {retries}/{self.MAX_RETRIES} after {self.RETRY_DELAY} seconds."
                    )
                    time.sleep(self.RETRY_DELAY)
                else:
                    logging.error(f"Error running Trivy for image {image}: {result.stderr}")
                    return None

            logging.error(
                f"Trivy scan failed after {self.MAX_RETRIES} retries for image {image}"
            )
            return None
        finally:
            if os.path.exists(processed_template):
                os.unlink(processed_template)


class GrypeScanner(ImageScanner):
    @property
    def label(self) -> str:
        return "Grype"

    def scan_image(self, image, config):
        html_file_path = self._register_html(image)
        allowed = {s.strip().upper() for s in config.severity_levels.split(",")}

        grype_cmd = ["grype", image, "-o", "json", "-q"]

        retries = 0
        while retries < self.MAX_RETRIES:
            logging.debug("Running command: %s", " ".join(grype_cmd))
            result = subprocess.run(grype_cmd, capture_output=True, text=True)

            if result.returncode == 0:
                logging.info(f"Grype scan completed for image {image}")
                break
            elif "TOOMANYREQUESTS" in result.stderr or "429" in result.stderr:
                retries += 1
                logging.warning(
                    f"Rate limit error for image {image}. Retrying {retries}/{self.MAX_RETRIES} after {self.RETRY_DELAY} seconds."
                )
                time.sleep(self.RETRY_DELAY)
            else:
                logging.error(
                    f"Error running Grype for image {repr(image)} (exit code {result.returncode}): {result.stderr.strip()}"
                )
                return None
        else:
            logging.error(
                f"Grype scan failed after {self.MAX_RETRIES} retries for image {image}"
            )
            return None

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse Grype JSON output for {image}: {e}")
            return None

        vulns = self._parse_vulnerabilities(data, allowed)
        os_vulns = sorted([v for v in vulns if v.is_os_package], key=lambda v: v.severity_rank)
        lib_vulns = sorted([v for v in vulns if not v.is_os_package], key=lambda v: v.severity_rank)

        html = self._vulns_to_html(image, os_vulns, lib_vulns, config.show_links)
        with open(html_file_path, "w") as f:
            f.write(html)
        return html_file_path

    @staticmethod
    def _parse_vulnerabilities(data, allowed) -> list[Vulnerability]:
        vulns = []
        for m in data.get("matches", []):
            sev = m.get("vulnerability", {}).get("severity", "Unknown").upper()
            if sev == "NEGLIGIBLE":
                sev = "LOW"
            if sev not in allowed:
                continue
            pkg = m.get("artifact", {})
            vuln = m.get("vulnerability", {})
            fix_versions = vuln.get("fix", {}).get("versions", [])
            vulns.append(Vulnerability(
                pkg_name=pkg.get("name", ""),
                vulnerability_id=vuln.get("id", ""),
                severity=sev,
                installed_version=pkg.get("version", ""),
                fixed_version=", ".join(fix_versions) if fix_versions else "",
                links=vuln.get("urls", []),
                pkg_type=pkg.get("type", "").lower(),
            ))
        return vulns

    @staticmethod
    def _vulns_to_html(image, os_vulns, lib_vulns, show_links):
        total_cols = 6 if show_links else 5
        lines = [f'    <h2 class="image-title">{_esc(image)}</h2>', "    <table>"]

        for section_name, vulns in [("OS Vulnerabilities", os_vulns), ("Library Vulnerabilities", lib_vulns)]:
            lines.append(
                f'      <tr class="group-header"><th colspan="{total_cols}">{section_name}</th></tr>'
            )
            if not vulns:
                lines.append(
                    f'      <tr><th colspan="{total_cols}">No Vulnerabilities found</th></tr>'
                )
            else:
                header_cols = "<th>Package</th><th>Vulnerability ID</th><th>Severity</th><th>Installed Version</th><th>Fixed Version</th>"
                if show_links:
                    header_cols += "<th>Links</th>"
                lines.append(f'      <tr class="sub-header">{header_cols}</tr>')
                for v in vulns:
                    links_td = ""
                    if show_links:
                        link_anchors = "".join(
                            f'<a href="{_esc(u)}">{_esc(u)}</a>' for u in v.links
                        )
                        links_td = f'<td class="links" data-more-links="off">{link_anchors}</td>'
                    lines.append(
                        f'      <tr class="severity-{_esc(v.severity)}">'
                        f'<td class="pkg-name">{_esc(v.pkg_name)}</td>'
                        f'<td>{_esc(v.vulnerability_id)}</td>'
                        f'<td class="severity">{_esc(v.severity)}</td>'
                        f'<td class="pkg-version">{_esc(v.installed_version)}</td>'
                        f'<td>{_esc(v.fixed_version)}</td>'
                        + links_td
                        + "</tr>"
                    )

        lines.append("    </table>")
        return "\n".join(lines)


SCANNER_CLASSES: dict[Scanner, type[ImageScanner]] = {
    Scanner.TRIVY: TrivyScanner,
    Scanner.GRYPE: GrypeScanner,
}


class VulnerabilityScanner:

    @staticmethod
    def get_all_images(repo, version=None):
        """Pull the chart to a temp dir, recursively scan all YAML files for image references."""
        tmp_dir = tempfile.mkdtemp(prefix="vuln-scan-")
        logging.info(f"Pulling chart to {tmp_dir}")

        try:
            if os.path.isfile(repo) and (
                repo.endswith(".tgz") or repo.endswith(".tar.gz")
            ):
                logging.info(f"Extracting local chart archive: {repo}")
                with tarfile.open(repo, "r:gz") as tar:
                    tar.extractall(path=tmp_dir, filter="data")
            elif os.path.isdir(repo):
                logging.info(f"Copying local chart directory: {repo}")
                chart_name = os.path.basename(os.path.abspath(repo))
                shutil.copytree(repo, os.path.join(tmp_dir, chart_name))
            else:
                pull_cmd = ["helm", "pull", repo, "--untar", "--destination", tmp_dir]
                if version:
                    pull_cmd += ["--version", version]
                logging.debug(f"Running: {' '.join(pull_cmd)}")
                result = subprocess.run(pull_cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    logging.error(
                        f"Helm pull failed (exit {result.returncode}):\n{result.stderr}"
                    )
                    return set()

            yaml_files = [
                f
                for f in glob.glob(
                    os.path.join(tmp_dir, "**", "*.yaml"), recursive=True
                )
                + glob.glob(os.path.join(tmp_dir, "**", "*.yml"), recursive=True)
                if os.sep + "charts" + os.sep in f
            ]
            logging.debug(f"Found {len(yaml_files)} YAML files in sub-charts")

            images = set()
            image_pattern = re.compile(
                r"""(?:image|repository)["']?\s*:\s*["']?([a-zA-Z0-9._\-/]+(?::[a-zA-Z0-9._\-]+)?)["']?"""
            )

            for yaml_file in yaml_files:
                try:
                    with open(yaml_file, "r") as f:
                        content = f.read()

                    try:
                        docs = list(yaml.safe_load_all(content))
                    except yaml.YAMLError:
                        docs = []

                    VulnerabilityScanner._extract_images_from_yaml(docs, images)

                    for line in content.splitlines():
                        stripped = line.strip()
                        if stripped.startswith("#"):
                            continue
                        match = image_pattern.search(stripped)
                        if match:
                            img = match.group(1).rstrip(":")
                            if "{{" not in img and img not in ("null", "None", ""):
                                images.add(img)

                except Exception as e:
                    logging.debug(f"Error reading {yaml_file}: {e}")

            images = {img.rstrip(":") for img in images}
            return images

        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @staticmethod
    def _extract_repo_tag(obj):
        """Extract a repo:tag image string from a dict with repository/tag keys."""
        repo = str(obj.get("repository", "")).rstrip(":")
        tag = str(obj.get("tag", "latest") or "latest").rstrip(":")
        if repo and "{{" not in repo and repo not in ("null", "None"):
            return f"{repo}:{tag}"
        return None

    @staticmethod
    def _extract_images_from_yaml(obj, images):
        """Recursively walk parsed YAML to find image references."""
        if isinstance(obj, dict):
            if "image" in obj and isinstance(obj["image"], dict):
                img = VulnerabilityScanner._extract_repo_tag(obj["image"])
                if img:
                    images.add(img)
            elif "image" in obj:
                val = obj["image"]
                if (
                    isinstance(val, str)
                    and "{{" not in val
                    and val not in ("null", "None", "")
                ):
                    images.add(val.rstrip(":"))

            if "repository" in obj and "tag" in obj and "image" not in obj:
                img = VulnerabilityScanner._extract_repo_tag(obj)
                if img:
                    images.add(img)

            for value in obj.values():
                VulnerabilityScanner._extract_images_from_yaml(value, images)
        elif isinstance(obj, list):
            for item in obj:
                VulnerabilityScanner._extract_images_from_yaml(item, images)

    def __init__(self, repo, version=None, registry=None, scanner_type=Scanner.TRIVY):
        self.images = self.get_all_images(repo, version)
        if registry:
            self.images = self._apply_registry(self.images, registry)
        self.scanner: ImageScanner = SCANNER_CLASSES[scanner_type]()

    @staticmethod
    def _apply_registry(images, registry):
        """Prefix images with the given registry. Strips existing registry if present."""
        registry = registry.rstrip("/")
        updated = set()
        for img in images:
            if ":" in img:
                name, tag = img.rsplit(":", 1)
            else:
                name, tag = img, "latest"

            tag = tag.strip() or "latest"

            parts = name.split("/")
            if "." in parts[0] or ":" in parts[0]:
                service_name = "/".join(parts[1:])
            else:
                service_name = name

            new_image = f"{registry}/{service_name}:{tag}"
            logging.debug(f"Registry rewrite: {img} -> {new_image}")
            updated.add(new_image)

        deduped = len(images) - len(updated)
        msg = f"Applied registry prefix: {registry} to {len(updated)} images"
        if deduped:
            msg += f" ({deduped} duplicates removed)"
        logging.info(msg)
        return updated

    @staticmethod
    def _get_report_shell(show_links=True, scanner_label="Trivy"):
        """Return (header, footer) HTML strings that wrap the per-image fragments."""
        title = f"{scanner_label} Vulnerability Report"
        links_script = ""
        if show_links:
            links_script = """
    <script>
      window.onload = function() {
        document.querySelectorAll('td.links').forEach(function(linkCell) {
          var links = [].concat.apply([], linkCell.querySelectorAll('a'));
          [].sort.apply(links, function(a, b) {
            return a.href > b.href ? 1 : -1;
          });
          links.forEach(function(link, idx) {
            if (links.length > 3 && 3 === idx) {
              var toggleLink = document.createElement('a');
              toggleLink.innerText = "Toggle more links";
              toggleLink.href = "#toggleMore";
              toggleLink.setAttribute("class", "toggle-more-links");
              linkCell.appendChild(toggleLink);
            }
            linkCell.appendChild(link);
          });
        });
        document.querySelectorAll('a.toggle-more-links').forEach(function(toggleLink) {
          toggleLink.onclick = function() {
            var expanded = toggleLink.parentElement.getAttribute("data-more-links");
            toggleLink.parentElement.setAttribute("data-more-links", "on" === expanded ? "off" : "on");
            return false;
          };
        });
      };
    </script>"""

        header = f"""<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: #f8f9fa;
            color: #212529;
            font-size: 13px;
            line-height: 1.4;
            padding: 16px;
        }}
        h1 {{
            text-align: center;
            font-size: 1.6em;
            font-weight: 700;
            margin: 12px 0 20px;
            color: #1a1a2e;
        }}
        .image-title {{
            font-size: 1.15em;
            font-weight: 600;
            margin: 18px 0 6px;
            padding: 6px 10px;
            color: #16213e;
            border-left: 4px solid #16213e;
            background-color: #e9ecef;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            table-layout: auto;
        }}
        th, td {{
            border: 1px solid #dee2e6;
            padding: 6px 10px;
            text-align: left;
            vertical-align: top;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }}
        .group-header th {{
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            color: #ffffff;
            font-size: 1.1em;
            font-weight: 600;
            padding: 10px 12px;
            text-align: left;
            letter-spacing: 0.02em;
        }}
        .sub-header th {{
            background-color: #e9ecef;
            color: #495057;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            padding: 6px 10px;
            white-space: nowrap;
        }}
        .severity {{
            display: inline-block;
            min-width: 68px;
            padding: 2px 8px;
            border-radius: 3px;
            font-weight: 600;
            font-size: 0.82em;
            text-align: center;
            color: #fff;
            letter-spacing: 0.03em;
        }}
        .severity-CRITICAL .severity {{ background-color: #dc3545; }}
        .severity-HIGH .severity     {{ background-color: #fd7e14; }}
        .severity-MEDIUM .severity   {{ background-color: #ffc107; color: #212529; }}
        .severity-LOW .severity      {{ background-color: #28a745; }}
        .severity-UNKNOWN .severity  {{ background-color: #6c757d; }}
        .severity-CRITICAL {{ background-color: #dc354510; }}
        .severity-HIGH     {{ background-color: #fd7e1410; }}
        .severity-MEDIUM   {{ background-color: #ffc10710; }}
        .severity-LOW      {{ background-color: #28a74510; }}
        .severity-UNKNOWN  {{ background-color: #6c757d10; }}
        tbody tr:hover {{
            background-color: #f1f3f5;
        }}
        .pkg-name {{
            font-weight: 600;
            color: #1a1a2e;
        }}
        .pkg-version, td:nth-child(5) {{
            font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
            font-size: 0.9em;
        }}
        tr th[colspan] {{
            text-align: center;
        }}
        td.links {{
            max-width: 260px;
            font-size: 0.82em;
        }}
        td.links a {{
            display: block;
            color: #0366d6;
            text-decoration: none;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            margin: 1px 0;
        }}
        td.links a:hover {{
            text-decoration: underline;
        }}
        td.links[data-more-links="off"] a:nth-child(n+4):not(.toggle-more-links) {{
            display: none;
        }}
        a.toggle-more-links {{
            color: #6c757d;
            font-style: italic;
            cursor: pointer;
            display: block;
            margin-top: 2px;
        }}
        td.link {{
            font-size: 0.88em;
            line-height: 1.35;
        }}
        td.link a {{
            color: #0366d6;
            word-break: break-all;
        }}
        hr {{
            border: none;
            border-top: 1px solid #dee2e6;
            margin: 8px 0;
        }}

        @media print {{
            body {{
                padding: 0;
                font-size: 9pt;
            }}
            .group-header th {{
                background: #1a1a2e !important;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }}
            .sub-header th {{
                background-color: #e9ecef !important;
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }}
            .severity {{
                -webkit-print-color-adjust: exact;
                print-color-adjust: exact;
            }}
            tr:hover {{
                background-color: transparent;
            }}
            table {{
                page-break-inside: auto;
            }}
            tr {{
                page-break-inside: avoid;
                page-break-after: auto;
            }}
        }}
    </style>
    <title>{title}</title>{links_script}
</head>
<body>
    <h1>{title}</h1>
"""

        footer = """
</body>
</html>
"""
        return header, footer

    def scan(self, config: ScanConfig):
        exclude_re = re.compile(config.exclude_regex) if config.exclude_regex else None

        scannable = [
            img for img in self.images
            if not any(p in img for p in config.exclude_patterns)
            and not (exclude_re and exclude_re.search(img))
        ]

        valid_image_re = re.compile(r'^[a-zA-Z0-9._\-/]+:[a-zA-Z0-9._\-]+$')
        cleaned = []
        for img in scannable:
            img = img.encode("ascii", "ignore").decode("ascii").strip().rstrip(":")
            if valid_image_re.match(img):
                cleaned.append(img)
            else:
                logging.warning(f"Skipping invalid image reference: {repr(img)}")
        scannable = cleaned

        excluded = len(self.images) - len(scannable)
        if excluded:
            reasons = []
            if config.exclude_patterns:
                reasons.append(f"substrings: {', '.join(config.exclude_patterns)}")
            if exclude_re:
                reasons.append(f"regex: {config.exclude_regex}")
            logging.info(
                f"Scanning {len(scannable)} images (excluded {excluded} matching {'; '.join(reasons)})"
            )
        else:
            logging.info(f"Scanning {len(scannable)} images")

        def scan_images(images):
            failed = []
            for image in images:
                try:
                    if self.scanner.scan_image(image, config) is None:
                        failed.append(image)
                except Exception as exc:
                    logging.error(f"Image {image} generated an exception: {exc}")
                    failed.append(image)
            return failed

        failed = scan_images(scannable)
        for attempt in range(1, config.retries + 1):
            if not failed:
                break
            logging.info(
                f"Retrying {len(failed)} failed images (attempt {attempt}/{config.retries})"
            )
            failed = scan_images(failed)

        if failed:
            logging.warning(
                f"{len(failed)} images failed after all retries: {', '.join(failed)}"
            )

        report_file_path = os.path.join(os.getcwd(), "report.html")
        header, footer = self._get_report_shell(
            show_links=config.show_links, scanner_label=self.scanner.label
        )
        written = 0
        with open(report_file_path, "w") as outfile:
            outfile.write(header)
            for html_file in self.scanner.html_files:
                if os.path.exists(html_file):
                    with open(html_file) as infile:
                        outfile.write(infile.read())
                    written += 1
                else:
                    logging.warning(f"Missing HTML report: {html_file}")
            outfile.write(footer)
        logging.info(
            f"Combined {written}/{len(self.scanner.html_files)} scan results into report"
        )

        self._sort_report_by_severity(report_file_path)

        for html_file in self.scanner.html_files:
            if os.path.exists(html_file):
                os.remove(html_file)

        pdf_report_path = report_file_path.replace(".html", ".pdf")
        chrome_path = self._find_chrome()
        if chrome_path:
            try:
                pdf_cmd = [
                    chrome_path,
                    "--headless",
                    "--disable-gpu",
                    "--no-sandbox",
                    "--print-to-pdf-no-header",
                    f"--print-to-pdf={pdf_report_path}",
                    report_file_path,
                ]
                logging.debug(f"Running: {' '.join(pdf_cmd)}")
                result = subprocess.run(
                    pdf_cmd, capture_output=True, text=True, timeout=120
                )
                if result.returncode == 0 and os.path.exists(pdf_report_path):
                    os.remove(report_file_path)
                    logging.info(
                        f"Vulnerability scanning complete. Report saved as {pdf_report_path}"
                    )
                else:
                    logging.warning(
                        f"PDF conversion failed: {result.stderr}. HTML report kept at {report_file_path}"
                    )
            except subprocess.TimeoutExpired:
                logging.warning(
                    f"PDF conversion timed out. HTML report kept at {report_file_path}"
                )
            except Exception as e:
                logging.warning(
                    f"PDF conversion error: {e}. HTML report kept at {report_file_path}"
                )
        else:
            logging.warning(
                "Chrome/Chromium not found. Install Google Chrome for PDF output."
            )
            logging.info(
                f"Vulnerability scanning complete. Report saved as {report_file_path}"
            )

        final_report = pdf_report_path if os.path.exists(pdf_report_path) else report_file_path
        if config.slack_token and config.slack_channel and os.path.exists(final_report):
            self._send_to_slack(
                final_report, config.slack_token, config.slack_channel,
                config.slack_mention, self.scanner.label,
            )

    @staticmethod
    def _sort_report_by_severity(report_file_path):
        """Sort vulnerability table rows by severity: CRITICAL > HIGH > MEDIUM > LOW."""
        try:
            with open(report_file_path, "r") as f:
                content = f.read()

            severity_row_pattern = re.compile(
                r'(<tr class="severity-(CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN)">.*?</tr>)',
                re.DOTALL,
            )
            sev_key = lambda r: Severity[r[1]].value if r[1] in Severity.__members__ else 99

            sections = re.split(
                r'(<tr class="sub-header">.*?</tr>)', content, flags=re.DOTALL
            )
            result_parts = []
            for section in sections:
                if 'class="sub-header"' in section:
                    result_parts.append(section)
                elif severity_row_pattern.search(section):
                    rows = severity_row_pattern.findall(section)
                    if rows:
                        rows.sort(key=sev_key)
                        sorted_rows = "\n      ".join(r[0] for r in rows)
                        cleaned = severity_row_pattern.sub("", section).rstrip()
                        result_parts.append(cleaned + "\n      " + sorted_rows)
                    else:
                        result_parts.append(section)
                else:
                    result_parts.append(section)

            with open(report_file_path, "w") as f:
                f.write("".join(result_parts))
            logging.info("Report sorted by severity level")
        except Exception as e:
            logging.warning(f"Could not sort report by severity: {e}")

    @staticmethod
    def _send_to_slack(report_path, slack_token, slack_channel, slack_mention=None, scanner_label="Trivy"):
        """Upload the report file to a Slack channel and optionally mention a user/group."""
        if not slack_token or not slack_channel:
            return

        logging.info(f"Uploading report to Slack channel {slack_channel}")
        message = f":rotating_light: *{scanner_label} Vulnerability Report*"
        if slack_mention:
            message = f"{slack_mention} {message}"

        try:
            file_size = os.path.getsize(report_path)
            file_name = os.path.basename(report_path)

            get_url_params = urllib.parse.urlencode(
                {"filename": file_name, "length": file_size}
            ).encode()
            get_url_req = urllib.request.Request(
                "https://slack.com/api/files.getUploadURLExternal",
                data=get_url_params,
                headers={
                    "Authorization": f"Bearer {slack_token}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                method="POST",
            )
            with urllib.request.urlopen(get_url_req) as resp:
                url_data = json.loads(resp.read().decode())

            if not url_data.get("ok"):
                logging.error(f"Slack getUploadURLExternal failed: {url_data.get('error')}")
                return

            upload_url = url_data["upload_url"]
            file_id = url_data["file_id"]

            with open(report_path, "rb") as f:
                file_data = f.read()

            upload_req = urllib.request.Request(
                upload_url,
                data=file_data,
                headers={"Content-Type": "application/octet-stream"},
                method="POST",
            )
            with urllib.request.urlopen(upload_req) as resp:
                resp.read()

            complete_payload = json.dumps(
                {
                    "files": [{"id": file_id, "title": file_name}],
                    "channel_id": slack_channel,
                    "initial_comment": message,
                }
            ).encode()
            complete_req = urllib.request.Request(
                "https://slack.com/api/files.completeUploadExternal",
                data=complete_payload,
                headers={
                    "Authorization": f"Bearer {slack_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(complete_req) as resp:
                complete_data = json.loads(resp.read().decode())

            if complete_data.get("ok"):
                logging.info("Report uploaded to Slack successfully.")
            else:
                logging.error(f"Slack completeUploadExternal failed: {complete_data.get('error')}")

        except Exception as e:
            logging.error(f"Failed to send report to Slack: {e}")

    @staticmethod
    def _find_chrome():
        candidates = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
        ]
        for candidate in candidates:
            if os.path.isfile(candidate) or shutil.which(candidate):
                return candidate
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Scan a Helm chart for vulnerabilities."
    )
    parser.add_argument("--repo", type=str, help="The Helm chart repository to scan.")
    parser.add_argument(
        "--scanner",
        type=lambda s: Scanner(s),
        choices=list(Scanner),
        required=True,
        help="Vulnerability scanner to use (trivy or grype).",
    )
    parser.add_argument(
        "--version",
        type=str,
        help="The version of the Helm chart to scan.",
        default=None,
    )
    parser.add_argument(
        "--registry",
        type=str,
        default=None,
        help="Registry prefix for images (e.g. <AWS_ACCOUNT_ID>.dkr.ecr.eu-central-1.amazonaws.com). "
        "Replaces existing registry in discovered image references.",
    )
    parser.add_argument(
        "--exclude-images",
        type=str,
        default="",
        help="Comma-separated list of substrings to exclude images (e.g. --exclude-images postgresql,redis).",
    )
    parser.add_argument(
        "--exclude-images-regex",
        type=str,
        default=None,
        help="Regex pattern to exclude matching images (e.g. --exclude-images-regex 'tickets-.*|legacy-').",
    )
    parser.add_argument(
        "--severity-levels",
        type=str,
        default="LOW,MEDIUM,HIGH,CRITICAL",
        help="Comma-separated severity levels to include (default: LOW,MEDIUM,HIGH,CRITICAL).",
    )
    parser.add_argument(
        "--show-links",
        action="store_true",
        default=False,
        help="Show vulnerability reference links in the report (default: hidden).",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="Number of times to retry failed image scans (default: 3).",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="The log level.",
    )
    parser.add_argument(
        "--slack-token",
        type=str,
        default=None,
        help="Slack Bot OAuth token (xoxb-...) for uploading the report. "
        "Requires chat:write and files:write scopes.",
    )
    parser.add_argument(
        "--slack-channel",
        type=str,
        default=None,
        help="Slack channel ID to send the report to (e.g. C0A6S3KNNLW).",
    )
    parser.add_argument(
        "--slack-mention",
        type=str,
        default=None,
        help="Slack mention to include in the message "
        '(e.g. "<!subteam^S0A6S3KNNLW>" for a user group, or "<@U012345>" for a user).',
    )
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level, format="[%(levelname)s] %(message)s")

    if not args.repo:
        parser.error("--repo argument is required.")

    exclude_patterns = (
        [p.strip() for p in args.exclude_images.split(",") if p.strip()]
        if args.exclude_images
        else []
    )

    config = ScanConfig(
        show_links=args.show_links,
        severity_levels=",".join(
            s.strip().upper() for s in args.severity_levels.split(",") if s.strip()
        ),
        retries=args.retries,
        exclude_patterns=exclude_patterns,
        exclude_regex=args.exclude_images_regex,
        slack_token=args.slack_token,
        slack_channel=args.slack_channel,
        slack_mention=args.slack_mention,
    )

    scanner = VulnerabilityScanner(args.repo, args.version, args.registry, args.scanner)
    scanner.scan(config)


if __name__ == "__main__":
    main()
