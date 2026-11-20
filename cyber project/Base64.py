
#!/usr/bin/env python3
"""Base64 Inspector - Safe Base64 analysis with a Tkinter GUI."""

import argparse
import base64
import binascii
import ipaddress
import re
import threading
import tkinter as tk

from pathlib import Path
from tkinter import ttk, filedialog, messagebox


# ---------------- CONFIGURATION ----------------

BASE64_RE = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])"
)

INDICATORS = {
    "URL": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    "IPv4 address": re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ),
    "PowerShell": re.compile(
        r"\bpowershell\b|\b-enc(?:odedcommand)?\b",
        re.IGNORECASE
    ),
    "Shell command": re.compile(
        r"\b(?:bash|sh|cmd\.exe|/bin/sh)\b",
        re.IGNORECASE
    ),
    "Windows path": re.compile(
        r"\b[A-Z]:\\(?:[^\\\s]+\\)[^\\\s]",
        re.IGNORECASE
    ),
}

MAX_FINDINGS = 10000


# ---------------- BASE64 FUNCTIONS ----------------

def decode_base64(value):
    """Decode Base64 with optional missing padding."""

    padded = value + "=" * (-len(value) % 4)

    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None


def describe(data):
    """Return readable text or a hexadecimal preview."""

    decoded = data.decode("utf-8", errors="replace")

    if decoded:
        printable = sum(
            char.isprintable() or char in "\r\n\t"
            for char in decoded
        ) / len(decoded)

        if printable > 0.85:
            return decoded.strip() or "(Empty decoded text)"

    return (
        f"(Binary data: {len(data)} bytes)\n"
        f"Hex preview: {data[:32].hex(' ')}"
    )


def get_indicators(text):
    """Identify potentially interesting strings."""

    matches = []

    for name, pattern in INDICATORS.items():
        found = pattern.findall(text)

        if name == "IPv4 address":
            valid_addresses = []

            for address in found:
                try:
                    ipaddress.IPv4Address(address)
                    valid_addresses.append(address)
                except ipaddress.AddressValueError:
                    pass

            if valid_addresses:
                matches.append(
                    f"{name}: {', '.join(dict.fromkeys(valid_addresses))}"
                )

        elif found:
            matches.append(
                f"{name}: {', '.join(dict.fromkeys(found[:5]))}"
            )

    return matches


def inspect_text(text, max_depth=3):
    """Recursively inspect Base64 without executing decoded content."""

    findings = []
    visited = set()

    def scan(current_text, depth, source):
        if depth > max_depth or len(findings) >= MAX_FINDINGS:
            return

        for match in BASE64_RE.finditer(current_text):

            if len(findings) >= MAX_FINDINGS:
                return

            candidate = match.group(0)

            # Avoid processing duplicate candidates at the same depth.
            key = (depth, candidate)

            if key in visited:
                continue

            visited.add(key)

            decoded = decode_base64(candidate)

            if decoded is None or not decoded:
                continue

            decoded_text = decoded.decode(
                "utf-8", errors="replace"
            )

            finding = {
                "number": len(findings) + 1,
                "depth": depth,
                "source": source,
                "offset": match.start(),
                "encoded": candidate,
                "decoded": describe(decoded),
                "indicators": get_indicators(decoded_text),
            }

            findings.append(finding)

            # Inspect nested Base64 only in decoded text.
            if depth < max_depth and decoded_text:
                scan(
                    decoded_text,
                    depth + 1,
                    f"Finding #{finding['number']}"
                )

    scan(text, 0, "Original file")

    return findings


# ---------------- REPORT GENERATION ----------------

def create_report(file_path, findings, max_depth):

    lines = [
        "=" * 65,
        "             BASE64 SECURITY INSPECTION REPORT",
        "=" * 65,
        f"File: {file_path}",
        f"Maximum recursion depth: {max_depth}",
        f"Total findings: {len(findings)}",
        "",
    ]

    for item in findings:

        lines.extend([
            "-" * 65,
            f"[Finding #{item['number']}]",
            f"Depth: {item['depth']}",
            f"Source: {item['source']}",
            f"Offset: {item['offset']}",
            "",
            "Encoded Base64:",
            item["encoded"],
            "",
            "Decoded content:",
            item["decoded"],
            "",
        ])

        if item["indicators"]:
            lines.append("Indicators:")

            for indicator in item["indicators"]:
                lines.append(f"  - {indicator}")
        else:
            lines.append("Indicators: None detected")

        lines.append("")

    lines.extend([
        "=" * 65,
        "Inspection completed. No decoded content was executed.",
        "=" * 65,
    ])

    return "\n".join(lines)


# ---------------- GUI APPLICATION ----------------

class Base64InspectorGUI:

    def __init__(self, root):

        self.root = root
        self.root.title("Base64 Inspector - Security Analysis")
        self.root.geometry("1050x720")
        self.root.minsize(750, 500)

        self.file_path = None
        self.findings = []
        self.report = ""

        self.create_widgets()

    def create_widgets(self):

        style = ttk.Style()

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Title.TLabel",
            font=("Segoe UI", 17, "bold")
        )

        style.configure(
            "Action.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=7
        )

        # Main container
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill=tk.BOTH, expand=True)

        # Title
        ttk.Label(
            main,
            text="Base64 Inspector",
            style="Title.TLabel"
        ).pack(anchor="w")

        ttk.Label(
            main,
            text="Safely detect and inspect encoded Base64 content."
        ).pack(anchor="w", pady=(3, 12))

        # File selection
        file_frame = ttk.LabelFrame(
            main,
            text="Input File",
            padding=10
        )
        file_frame.pack(fill=tk.X, pady=5)

        self.file_label = ttk.Label(
            file_frame,
            text="No file selected",
            wraplength=700
        )
        self.file_label.pack(
            side=tk.LEFT,
            fill=tk.X,
            expand=True
        )

        ttk.Button(
            file_frame,
            text="Browse",
            command=self.select_file,
            style="Action.TButton"
        ).pack(side=tk.RIGHT, padx=5)

        # Settings
        settings = ttk.Frame(main)
        settings.pack(fill=tk.X, pady=8)

        ttk.Label(
            settings,
            text="Maximum recursion depth:"
        ).pack(side=tk.LEFT)

        self.depth_var = tk.IntVar(value=3)

        self.depth_spin = ttk.Spinbox(
            settings,
            from_=0,
            to=10,
            width=5,
            textvariable=self.depth_var
        )
        self.depth_spin.pack(side=tk.LEFT, padx=8)

        # Buttons
        button_frame = ttk.Frame(main)
        button_frame.pack(fill=tk.X, pady=5)

        self.scan_button = ttk.Button(
            button_frame,
            text="Start Inspection",
            command=self.start_scan,
            style="Action.TButton"
        )
        self.scan_button.pack(side=tk.LEFT, padx=3)

        self.save_button = ttk.Button(
            button_frame,
            text="Export Report",
            command=self.save_report,
            state=tk.DISABLED,
            style="Action.TButton"
        )
        self.save_button.pack(side=tk.LEFT, padx=3)

        ttk.Button(
            button_frame,
            text="Clear Results",
            command=self.clear_results
        ).pack(side=tk.LEFT, padx=3)

        # Progress
        self.status_var = tk.StringVar(
            value="Ready"
        )

        ttk.Label(
            main,
            textvariable=self.status_var
        ).pack(anchor="w", pady=(8, 3))

        self.progress = ttk.Progressbar(
            main,
            mode="indeterminate"
        )
        self.progress.pack(fill=tk.X, pady=3)

        # Results
        result_frame = ttk.LabelFrame(
            main,
            text="Inspection Results",
            padding=5
        )
        result_frame.pack(
            fill=tk.BOTH,
            expand=True,
            pady=8
        )

        self.output = tk.Text(
            result_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#171923",
            fg="#e6e6e6",
            insertbackground="white",
            padx=10,
            pady=10
        )

        scrollbar = ttk.Scrollbar(
            result_frame,
            orient=tk.VERTICAL,
            command=self.output.yview
        )

        self.output.configure(
            yscrollcommand=scrollbar.set
        )

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.output.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )

        self.output.insert(
            tk.END,
            "Welcome to Base64 Inspector.\n\n"
            "1. Select a text file.\n"
            "2. Choose the maximum recursion depth.\n"
            "3. Click Start Inspection.\n"
            "4. Export the report when finished.\n\n"
            "Decoded content is displayed as data only. "
            "It is never executed.\n"
        )

    # ---------------- FILE SELECTION ----------------

    def select_file(self):

        selected = filedialog.askopenfilename(
            title="Select a text file",
            filetypes=[
                ("Text files", "*.txt *.log *.csv *.json *.xml *.ps1"),
                ("All files", "*.*")
            ]
        )

        if selected:
            self.file_path = Path(selected)

            self.file_label.config(
                text=str(self.file_path)
            )

    # ---------------- START INSPECTION ----------------

    def start_scan(self):

        if not self.file_path:
            messagebox.showwarning(
                "Missing file",
                "Please select a file first."
            )
            return

        try:
            depth = self.depth_var.get()

            if not 0 <= depth <= 10:
                raise ValueError

        except (ValueError, tk.TclError):
            messagebox.showerror(
                "Invalid depth",
                "Recursion depth must be between 0 and 10."
            )
            return

        self.scan_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.DISABLED)

        self.output.delete("1.0", tk.END)

        self.status_var.set("Inspecting file...")
        self.progress.start(10)

        # Run file inspection in a background thread.
        worker = threading.Thread(
            target=self.scan_worker,
            args=(self.file_path, depth),
            daemon=True
        )
        worker.start()

    def scan_worker(self, path, depth):

        try:
            text = path.read_text(
                encoding="utf-8",
                errors="replace"
            )

            findings = inspect_text(
                text,
                max_depth=depth
            )

            report = create_report(
                path,
                findings,
                depth
            )

            self.root.after(
                0,
                lambda: self.scan_complete(
                    findings,
                    report
                )
            )

        except (OSError, UnicodeError) as error:

            self.root.after(
                0,
                lambda: self.scan_error(str(error))
            )

    # ---------------- DISPLAY RESULTS ----------------

    def scan_complete(self, findings, report):

        self.findings = findings
        self.report = report

        self.progress.stop()
        self.scan_button.config(state=tk.NORMAL)

        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, report)

        self.status_var.set(
            f"Completed: {len(findings)} Base64 finding(s)"
        )

        self.save_button.config(
            state=tk.NORMAL
        )

        messagebox.showinfo(
            "Inspection completed",
            f"Inspection finished.\n\n"
            f"Base64 findings: {len(findings)}"
        )

    def scan_error(self, error):

        self.progress.stop()
        self.scan_button.config(state=tk.NORMAL)

        self.status_var.set("Inspection failed")

        messagebox.showerror(
            "File error",
            f"Could not inspect the file:\n\n{error}"
        )

    # ---------------- EXPORT REPORT ----------------

    def save_report(self):

        if not self.report:
            messagebox.showwarning(
                "No report",
                "Run an inspection first."
            )
            return

        destination = filedialog.asksaveasfilename(
            title="Save inspection report",
            defaultextension=".txt",
            filetypes=[
                ("Text report", "*.txt"),
                ("All files", "*.*")
            ]
        )

        if not destination:
            return

        try:
            Path(destination).write_text(
                self.report,
                encoding="utf-8"
            )

            messagebox.showinfo(
                "Report saved",
                f"Report saved successfully:\n{destination}"
            )

        except OSError as error:

            messagebox.showerror(
                "Save error",
                str(error)
            )

    # ---------------- CLEAR RESULTS ----------------

    def clear_results(self):

        self.findings = []
        self.report = ""

        self.output.delete("1.0", tk.END)

        self.status_var.set("Ready")

        self.save_button.config(
            state=tk.DISABLED
        )


# ---------------- MAIN ----------------

def main():

    parser = argparse.ArgumentParser(
        description="Base64 Inspector GUI"
    )

    parser.add_argument(
        "--file",
        type=Path,
        help="Optional input file to preselect"
    )

    args = parser.parse_args()

    root = tk.Tk()

    app = Base64InspectorGUI(root)

    if args.file:
        if args.file.is_file():
            app.file_path = args.file
            app.file_label.config(text=str(args.file))
        else:
            messagebox.showwarning(
                "File not found",
                f"Could not find: {args.file}"
            )

    root.mainloop()


if __name__ == "__main__":
    main()
