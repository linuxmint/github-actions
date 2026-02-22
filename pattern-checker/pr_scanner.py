#!/usr/bin/env python3

import sys
import os
import json
import re
import hashlib
import subprocess
import fnmatch
import argparse
from pathlib import Path

try:
    import yaml
except ImportError:
    print("pyyaml is required: pip3 install pyyaml", file=sys.stderr)
    sys.exit(1)

SCRIPT_DIR = Path(os.path.dirname(os.path.realpath(__file__)))

SEVERITY_COLORS = {
    "warning": "\033[33m",  # yellow
    "info": "\033[36m",     # cyan
}
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_DIM = "\033[2m"


class PatternChecker:
    def __init__(self, config_file=None, file_extensions=None):
        self.config_file = config_file
        self.file_extensions = file_extensions
        self.findings = []
        self.config = None

    def load_config(self):
        base_path = SCRIPT_DIR

        config_path = base_path / "patterns.yml"
        if config_path.exists():
            with open(config_path, "r") as f:
                self.config = yaml.safe_load(f) or {}
        else:
            self.config = {}

        self.config.setdefault("settings", {})
        self.config["patterns"] = []

        patterns_dir = base_path / "patterns"
        if patterns_dir.is_dir():
            for pattern_file in sorted(patterns_dir.glob("*.yml")):
                with open(pattern_file, "r") as f:
                    data = yaml.safe_load(f)
                if data and "patterns" in data:
                    self.config["patterns"].extend(data["patterns"])
                    print(f"  Loaded {len(data['patterns']):>2} patterns from {pattern_file.name}")

        if self.config_file and self.config_file.strip():
            custom_path = Path(self.config_file)
            if custom_path.exists():
                with open(custom_path, "r") as f:
                    custom = yaml.safe_load(f)
                if custom:
                    if "patterns" in custom:
                        self.config["patterns"].extend(custom["patterns"])
                        print(f"  Loaded {len(custom['patterns']):>2} patterns from {custom_path}")
                    if "settings" in custom:
                        self.config["settings"].update(custom["settings"])
            else:
                print(f"Warning: Custom config file not found: {custom_path}", file=sys.stderr)

        if not self.config["patterns"]:
            print("Warning: No patterns loaded", file=sys.stderr)

        print(f"  Total: {len(self.config['patterns'])} patterns\n")

    def should_check_file(self, filename, pattern):
        settings = self.config.get("settings", {})
        exclude_patterns = settings.get("exclude_patterns", [])

        for exclude_pattern in exclude_patterns:
            if fnmatch.fnmatch(filename, exclude_pattern):
                return False

        extensions = pattern.get("extensions", [])
        if not extensions:
            return True

        if self.file_extensions and self.file_extensions.strip():
            extensions = [ext.strip() for ext in self.file_extensions.split(",")]

        file_ext = os.path.splitext(filename)[1]
        return file_ext in extensions

    def find_patterns_in_patch(self, filename, patch, pattern):
        if not patch:
            return []

        findings = []
        lines = patch.split("\n")
        current_line_num = 0
        regex = re.compile(pattern["regex"])
        max_findings = self.config.get("settings", {}).get("max_findings_per_file", 10)

        for line in lines:
            if line.startswith("@@"):
                match = re.search(r"\+(\d+)", line)
                if match:
                    current_line_num = int(match.group(1)) - 1
            elif line.startswith("+") and not line.startswith("+++"):
                current_line_num += 1
                line_content = line[1:]

                if regex.search(line_content):
                    if len(findings) < max_findings:
                        findings.append({
                            "line_num": current_line_num,
                            "line_content": line_content,
                            "pattern": pattern,
                        })
            elif not line.startswith("-"):
                current_line_num += 1

        return findings

    def check_files(self, file_patches):
        for filename, patch in file_patches.items():
            for pattern in self.config["patterns"]:
                if not self.should_check_file(filename, pattern):
                    continue

                findings = self.find_patterns_in_patch(filename, patch, pattern)
                for finding in findings:
                    self.findings.append({
                        "filename": filename,
                        "line_num": finding["line_num"],
                        "line_content": finding["line_content"],
                        "pattern_name": pattern["name"],
                        "message": pattern.get("message", "Pattern detected"),
                        "severity": pattern.get("severity", "warning"),
                    })

    def format_terminal(self):
        if not self.findings:
            return None

        by_severity = {"warning": [], "info": []}
        for finding in self.findings:
            severity = finding["severity"]
            by_severity.setdefault(severity, []).append(finding)

        lines = []

        for severity in ("warning", "info"):
            severity_findings = by_severity.get(severity, [])
            if not severity_findings:
                continue

            color = SEVERITY_COLORS.get(severity, "")

            by_pattern = {}
            for finding in severity_findings:
                name = finding["pattern_name"]
                by_pattern.setdefault(name, []).append(finding)

            for pattern_name, pattern_findings in by_pattern.items():
                label = "WARNING" if severity == "warning" else "INFO"
                lines.append(f"{color}{COLOR_BOLD}[{label}] {pattern_name}{COLOR_RESET}")

                message = pattern_findings[0]["message"].strip()
                for msg_line in message.split("\n"):
                    lines.append(f"  {COLOR_DIM}{msg_line.strip()}{COLOR_RESET}")
                lines.append("")

                for finding in pattern_findings:
                    lines.append(f"  {finding['filename']}:{finding['line_num']}")
                    lines.append(f"    {color}{finding['line_content'].rstrip()}{COLOR_RESET}")
                lines.append("")

        return "\n".join(lines)

    def _make_diff_link(self, filename, line_num, repository, event_type, ref):
        file_hash = hashlib.sha256(filename.encode()).hexdigest()
        anchor = f"diff-{file_hash}R{line_num}"

        if event_type == "pull_request":
            return f"https://github.com/{repository}/pull/{ref}/files#{anchor}"
        else:
            return f"https://github.com/{repository}/commit/{ref}#{anchor}"

    def format_github_comment(self, repository=None, event_type=None, ref=None):
        if not self.findings:
            return None

        comment = "## Best-practices scanner\n\n"
        comment += "This is a regex-based check for API usage that can pose security, performance or\n";
        comment += "maintainability issues, or that may already be provided by Cinnamon. Having code flagged\n";
        comment += "by it doesn't automatically disqualify a pull request.\n\n";
        comment += "### This check is not perfect will not replace a normal review.\n";
        comment += "---\n"
        comment += f"Found {len(self.findings)} potential issue(s):\n\n"

        by_pattern = {}
        for finding in self.findings:
            pattern_name = finding["pattern_name"]
            by_pattern.setdefault(pattern_name, []).append(finding)

        for pattern_name, pattern_findings in by_pattern.items():
            severity_emoji = ":warning:" if pattern_findings[0]["severity"] == "warning" else ":information_source:"
            comment += f"### {severity_emoji} {pattern_name}\n\n"

            for finding in pattern_findings:
                if repository and event_type and ref:
                    link = self._make_diff_link(finding['filename'], finding['line_num'], repository, event_type, ref)
                    comment += f"**[{finding['filename']}:{finding['line_num']}]({link})**\n"
                else:
                    comment += f"**{finding['filename']}:{finding['line_num']}**\n"
                comment += f"```\n{finding['line_content'].strip()}\n```\n"
                comment += f"{finding['message']}\n\n"

        comment += "---\n"
        comment += "*Automated pattern check.*\n"
        return comment


def parse_git_diff(diff_text):
    file_patches = {}
    current_file = None
    current_patch_lines = []

    for line in diff_text.split("\n"):
        if line.startswith("diff --git"):
            if current_file and current_patch_lines:
                file_patches[current_file] = "\n".join(current_patch_lines)
            current_file = None
            current_patch_lines = []
        elif line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("+++ /dev/null"):
            current_file = None
        elif current_file is not None:
            current_patch_lines.append(line)

    if current_file and current_patch_lines:
        file_patches[current_file] = "\n".join(current_patch_lines)

    return file_patches


def get_git_diff(ref):
    if ".." in ref:
        cmd = ["git", "diff", ref]
    else:
        cmd = ["git", "show", "--format=", ref]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running {' '.join(cmd)}:", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)

    return result.stdout


def get_github_diff(github_token, repository, event_type, ref):
    try:
        import requests
    except ImportError:
        print("requests is required for GitHub mode: pip3 install requests", file=sys.stderr)
        sys.exit(1)

    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
    }

    if event_type == "pull_request":
        url = f"https://api.github.com/repos/{repository}/pulls/{ref}/files"
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"Failed to get PR files: {response.status_code}", file=sys.stderr)
            sys.exit(1)
        file_patches = {}
        for f in response.json():
            file_patches[f["filename"]] = f.get("patch", "")
        return file_patches
    else:
        url = f"https://api.github.com/repos/{repository}/commits/{ref}"
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print(f"Failed to get commit: {response.status_code}", file=sys.stderr)
            sys.exit(1)
        file_patches = {}
        for f in response.json().get("files", []):
            file_patches[f["filename"]] = f.get("patch", "")
        return file_patches


def run_github_action():
    github_token = os.environ.get("PATTERN_CHECK_TOKEN")
    config_file = os.environ.get("PATTERN_CHECK_CONFIG", "")
    file_extensions = os.environ.get("PATTERN_CHECK_EXTENSIONS", "")
    only_warn = os.environ.get("PATTERN_CHECK_ONLY_WARN", "true").lower() == "true"

    checker = PatternChecker(config_file=config_file, file_extensions=file_extensions)
    print("Loading patterns...")
    checker.load_config()

    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path or not os.path.exists(event_path):
        print("::error::GITHUB_EVENT_PATH not found", file=sys.stderr)
        sys.exit(0 if only_warn else 1)

    with open(event_path, "r") as f:
        event = json.load(f)

    repository = os.environ.get("GITHUB_REPOSITORY")
    event_name = os.environ.get("GITHUB_EVENT_NAME")

    if "pull_request" in event:
        event_type = "pull_request"
        ref = event["pull_request"]["number"]
        print(f"Checking PR #{ref} in {repository}")
    elif event_name == "push":
        event_type = "push"
        ref = event.get("after", os.environ.get("GITHUB_SHA"))
        print(f"Checking commit {ref[:7]} in {repository}")
    else:
        print("::notice::Event type not supported for pattern checking")
        sys.exit(0)

    file_patches = get_github_diff(github_token, repository, event_type, ref)
    print(f"Found {len(file_patches)} changed files")

    checker.check_files(file_patches)

    if checker.findings:
        print(f"::warning::Found {len(checker.findings)} pattern matches")
        comment = checker.format_github_comment(repository, event_type, ref)
        if comment:
            try:
                import requests
            except ImportError:
                print(comment)
                sys.exit(0 if only_warn else 1)

            headers = {
                "Authorization": f"token {github_token}",
                "Accept": "application/vnd.github.v3+json",
            }

            if event_type == "pull_request":
                url = f"https://api.github.com/repos/{repository}/issues/{ref}/comments"
            else:
                url = f"https://api.github.com/repos/{repository}/commits/{ref}/comments"

            response = requests.post(url, headers=headers, json={"body": comment})
            if response.status_code == 201:
                print(f"::notice::Posted pattern check results")
            else:
                print(f"::error::Failed to post comment: {response.status_code}")

        if not only_warn:
            sys.exit(1)
    else:
        print("::notice::No pattern matches found")


def main():
    parser = argparse.ArgumentParser(
        description="Scan git diffs for problematic code patterns.",
        epilog="Examples:\n"
               "  %(prog)s abc123              Scan a single commit\n"
               "  %(prog)s main..feature       Scan a branch range\n"
               "  %(prog)s HEAD~3..HEAD        Scan last 3 commits\n"
               "  %(prog)s HEAD                Scan the latest commit\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("ref", help="Commit SHA, range (base..head), or branch name")
    parser.add_argument("-c", "--config", help="Path to custom pattern config file", default="")
    parser.add_argument("-e", "--extensions", help="Comma-separated file extensions to check", default="")
    args = parser.parse_args()

    checker = PatternChecker(config_file=args.config, file_extensions=args.extensions)
    print("Loading patterns...")
    checker.load_config()

    print(f"Scanning: {args.ref}")
    diff_text = get_git_diff(args.ref)
    file_patches = parse_git_diff(diff_text)
    print(f"Found {len(file_patches)} changed files\n")

    checker.check_files(file_patches)

    if checker.findings:
        output = checker.format_terminal()
        if output:
            print(output)
        print(f"{COLOR_BOLD}Total: {len(checker.findings)} findings{COLOR_RESET}")
        sys.exit(1)
    else:
        print("No pattern matches found.")
        sys.exit(0)


if __name__ == "__main__":
    if os.environ.get("GITHUB_ACTIONS"):
        run_github_action()
    else:
        main()
