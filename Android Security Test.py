#!/usr/bin/env python3
"""
MOBILE SECURITY INSPECTOR
A read-only desktop security assessment utility for Android (ADB) and iOS
(libimobiledevice). It is a triage tool, not a full penetration-testing suite.

Requirements:
  Python 3.10+
  Android: Android Platform Tools (adb) installed and USB debugging authorized
  iOS: libimobiledevice installed (idevice_id / ideviceinfo); device trusted
  PDF reports: reportlab
  PDF report import: pypdf (optional)

Run:
  python mobile_security_inspector.py
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
import zipfile
import platform
import queue
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_NAME = "MOBILE SECURITY INSPECTOR"
BG = "#080D18"
PANEL = "#101A2B"
PANEL2 = "#142238"
TEXT = "#E7F0FA"
MUTED = "#8DA2BA"
CYAN = "#36D9F5"
GREEN = "#42D392"
AMBER = "#F5B942"
RED = "#FF637D"
PURPLE = "#B69CFF"

@dataclass
class Finding:
    category: str
    title: str
    status: str
    severity: str
    details: str
    impact: str
    recommendation: str

@dataclass
class Device:
    platform: str
    identifier: str
    model: str = "Unknown"
    manufacturer: str = "Unknown"
    os_version: str = "Unknown"
    build: str = "Unknown"
    serial: str = "Not exposed"
    connection: str = "USB"
    extra: dict | None = None

def find_tool(name):
    """Find command-line tools even when the GUI was launched outside Terminal."""
    found = shutil.which(name)
    if found:
        return found
    candidates = []
    home = Path.home()
    if name == "adb":
        candidates += [
            home / "Library/Android/sdk/platform-tools/adb",
            home / "Android/Sdk/platform-tools/adb",
            home / "Android/platform-tools/adb",
            home / "Downloads/platform-tools/adb",
            Path("/opt/homebrew/bin/adb"),
            Path("/usr/local/bin/adb"),  # Homebrew on Intel Macs
            Path("/opt/local/bin/adb"),
        ]
    elif name in ("idevice_id", "ideviceinfo"):
        candidates += [Path("/opt/homebrew/bin") / name,
                       Path("/usr/local/bin") / name,
                       Path("/opt/local/bin") / name]
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None

def run_cmd(args, timeout=5):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return 127, "", str(e)

def adb_devices():
    adb = find_tool("adb")
    if not adb:
        return []
    # Starting the ADB server is safe; it does not change the phone.
    run_cmd([adb, "start-server"], 8)
    rc, out, err = run_cmd([adb, "devices", "-l"], 8)
    result = []
    if rc == 0:
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line or line.startswith("*") or line.startswith("List of"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                result.append((parts[0], parts[1], line))
    return result

def detect_ios():
    tool = find_tool("idevice_id")
    if not tool:
        return []
    rc, out, _ = run_cmd([tool, "-l"], 8)
    return [x.strip() for x in out.splitlines() if x.strip()] if rc == 0 else []

def adb_prop(serial, prop):
    adb = find_tool("adb")
    if not adb:
        return "Unknown"
    rc, out, _ = run_cmd([adb, "-s", serial, "shell", "getprop", prop], 5)
    return out if rc == 0 and out else "Unknown"

def identify_android(serial):
    state = next((x[1] for x in adb_devices() if x[0] == serial), "unknown")
    if state != "device":
        return Device("Android", serial, model="Device detected — authorization required",
                      connection=f"USB / {state}")
    return Device(
        "Android", serial,
        model=adb_prop(serial, "ro.product.model"),
        manufacturer=adb_prop(serial, "ro.product.manufacturer"),
        os_version=adb_prop(serial, "ro.build.version.release"),
        build=adb_prop(serial, "ro.build.display.id"),
        serial=serial,
        extra={"sdk": adb_prop(serial, "ro.build.version.sdk"),
               "security_patch": adb_prop(serial, "ro.build.version.security_patch"),
               "verified_boot": adb_prop(serial, "ro.boot.verifiedbootstate"),
               "bootloader": adb_prop(serial, "ro.boot.flash.locked")}
    )

def identify_ios(udid):
    info = {}
    if shutil.which("ideviceinfo"):
        rc, out, err = run_cmd(["ideviceinfo", "-u", udid], 8)
        if rc == 0:
            for line in out.splitlines():
                if ": " in line:
                    k, v = line.split(": ", 1)
                    info[k.strip()] = v.strip()
    return Device("iOS", udid,
        model=info.get("ProductType", "iPhone/iPad (model unavailable)"),
        manufacturer="Apple",
        os_version=info.get("ProductVersion", "Unknown"),
        build=info.get("BuildVersion", "Unknown"),
        serial=info.get("SerialNumber", "Restricted by iOS"),
        extra={"device_name": info.get("DeviceName", "Unknown"),
               "product_name": info.get("ProductName", "Unknown"),
               "note": "iOS limits diagnostic access over USB."})

def adb_shell(serial, command, timeout=4):
    adb = find_tool("adb")
    if not adb:
        return 127, "", "ADB executable not found"
    return run_cmd([adb, "-s", serial, "shell"] + command.split(), timeout)

def assess_android(device: Device, emit):
    """Expanded Android posture audit using read-only ADB queries."""
    serial = device.identifier
    findings = []

    def add(category, title, status, severity, details, impact, recommendation):
        item = Finding(category, title, status, severity, details, impact, recommendation)
        findings.append(item)
        emit(item)

    def query(command, timeout=5):
        return adb_shell(serial, command, timeout)

    def property_value(name):
        rc, value, err = query(f"getprop {name}", 5)
        return value if rc == 0 and value else "Unknown"

    add("Connection", "ADB host authorization", "PASS", "INFO",
        "The connected Android device is authorized for ADB communication.",
        "An authorized host can invoke debugging interfaces while USB debugging is enabled.",
        "Disable USB debugging after the assessment and revoke authorizations for computers you no longer trust.")

    # OS identity and patch age
    patch = (device.extra or {}).get("security_patch", "Unknown")
    if patch not in ("", "Unknown"):
        try:
            patch_date = datetime.strptime(patch[:10], "%Y-%m-%d").date()
            age = (datetime.now().date() - patch_date).days
            if age > 180:
                status, severity = "FAIL", "HIGH"
            elif age > 90:
                status, severity = "WARNING", "MEDIUM"
            else:
                status, severity = "PASS", "INFO"
            add("OS & Updates", "Android security patch freshness", status, severity,
                f"Device reports patch level {patch}; calculated age: {age} days.",
                "A stale patch level can leave publicly known platform vulnerabilities unpatched. This check does not map the device to individual CVEs.",
                "Install the newest official system/security update offered for this exact model and region.")
        except ValueError:
            add("OS & Updates", "Android security patch freshness", "NOT TESTED", "INFO",
                f"Patch-level value was not parseable: {patch}.", "Patch age cannot be established.",
                "Check Settings > Security > Security update and confirm with the manufacturer.")
    else:
        add("OS & Updates", "Android security patch freshness", "NOT TESTED", "INFO",
            "The device did not expose a security patch level through ADB.",
            "Patch freshness and known-CVE exposure cannot be established.",
            "Check the security update date in Settings and the manufacturer's support page.")

    # Encryption
    crypto = property_value("ro.crypto.state").lower()
    if crypto == "encrypted":
        add("Data Protection", "User-data encryption state", "PASS", "INFO",
            "Android property ro.crypto.state reports encrypted.",
            "Encryption helps protect stored data when the device is locked and properly configured.",
            "Maintain a strong screen-lock credential and keep the OS updated.")
    elif crypto == "unencrypted":
        add("Data Protection", "User-data encryption state", "FAIL", "CRITICAL",
            "Android property ro.crypto.state reports unencrypted.",
            "Data stored on the device may be exposed if an attacker obtains physical access.",
            "Back up important data and follow the manufacturer's supported process to enable encryption.")
    else:
        add("Data Protection", "User-data encryption state", "NOT TESTED", "INFO",
            f"Encryption property returned {crypto!r}.", "Encryption could not be verified.",
            "Verify encryption in Android security settings; do not treat an unknown value as a pass.")

    # Verified boot and bootloader
    vb = (device.extra or {}).get("verified_boot", "Unknown").lower()
    if vb == "green":
        add("Platform Integrity", "Verified Boot state", "PASS", "INFO",
            "ro.boot.verifiedbootstate reports green.",
            "Green is a positive verified-boot signal, but it does not prove the device is free of compromise.",
            "Keep the bootloader locked and use manufacturer-signed firmware.")
    elif vb in ("orange", "yellow", "red"):
        add("Platform Integrity", "Verified Boot state", "WARNING", "HIGH",
            f"Verified Boot property reports {vb!r}.",
            "A non-green state can indicate an unlocked bootloader, custom trust configuration, or verification warning.",
            "Confirm whether this state is intentional. If not, restore official firmware using OEM instructions.")
    else:
        add("Platform Integrity", "Verified Boot state", "NOT TESTED", "INFO",
            f"Verified Boot state unavailable ({vb}).", "Boot-chain integrity is unknown.",
            "Review the boot warning screen and manufacturer bootloader documentation.")

    boot_lock = (device.extra or {}).get("bootloader", "Unknown")
    if boot_lock == "1":
        add("Platform Integrity", "Bootloader lock indicator", "PASS", "INFO",
            "ro.boot.flash.locked reports 1.", "A locked bootloader helps prevent unauthorized firmware replacement.",
            "Keep the bootloader locked unless there is a deliberate development requirement.")
    elif boot_lock == "0":
        add("Platform Integrity", "Bootloader lock indicator", "WARNING", "HIGH",
            "ro.boot.flash.locked reports 0.", "An unlocked bootloader can make modified system images easier to load.",
            "If not intentional, follow the device maker's official stock-firmware and relocking procedure.")
    else:
        add("Platform Integrity", "Bootloader lock indicator", "NOT TESTED", "INFO",
            f"Bootloader lock property unavailable ({boot_lock}).", "Bootloader state cannot be confirmed.",
            "Check the bootloader status using the manufacturer's supported method.")

    # SELinux
    rc, selinux, err = query("getenforce")
    if rc == 0 and selinux.lower() == "enforcing":
        add("Platform Hardening", "SELinux enforcement", "PASS", "INFO",
            "getenforce reports Enforcing.", "SELinux policy enforcement helps contain application and service compromise.",
            "Keep SELinux enforcing; do not use permissive mode on a production device.")
    elif rc == 0 and selinux.lower() == "permissive":
        add("Platform Hardening", "SELinux enforcement", "FAIL", "HIGH",
            "getenforce reports Permissive.", "SELinux violations may be logged rather than blocked, weakening isolation.",
            "Restore enforcing mode using a supported stock configuration; avoid unofficial policy changes.")
    else:
        add("Platform Hardening", "SELinux enforcement", "NOT TESTED", "INFO",
            f"SELinux state unavailable ({selinux or err or 'no response'}).", "Mandatory access-control enforcement is unknown.",
            "Verify SELinux state with the device manufacturer or a trusted device-management tool.")

    # Debuggable / secure build flags and test keys
    debuggable = property_value("ro.debuggable")
    secure = property_value("ro.secure")
    tags = property_value("ro.build.tags")
    if debuggable == "1":
        add("Platform Hardening", "Debuggable system build flag", "WARNING", "HIGH",
            "ro.debuggable is 1.", "A debuggable production image may expose additional diagnostic capabilities.",
            "Use the manufacturer's production firmware; investigate if this is not a development device.")
    elif debuggable == "0":
        add("Platform Hardening", "Debuggable system build flag", "PASS", "INFO",
            "ro.debuggable is 0.", "This is the expected setting on a production Android build.",
            "Keep the device on official production firmware.")
    else:
        add("Platform Hardening", "Debuggable system build flag", "NOT TESTED", "INFO",
            f"ro.debuggable returned {debuggable}.", "Build debug posture is unknown.",
            "Verify the build type with the device manufacturer.")

    if secure == "0":
        add("Platform Hardening", "Android secure build flag", "WARNING", "HIGH",
            "ro.secure is 0.", "A non-secure build configuration can weaken platform protections.",
            "Use official production firmware and investigate unexpected engineering builds.")
    elif secure == "1":
        add("Platform Hardening", "Android secure build flag", "PASS", "INFO",
            "ro.secure is 1.", "This is the expected production-oriented setting.",
            "Continue using official signed firmware.")
    else:
        add("Platform Hardening", "Android secure build flag", "NOT TESTED", "INFO",
            f"ro.secure returned {secure}.", "Secure build posture is unknown.",
            "Confirm the firmware build type with the OEM.")

    if "test-keys" in tags.lower():
        add("Platform Integrity", "Firmware signing tag", "WARNING", "MEDIUM",
            f"Build tags contain {tags!r}.", "Test-key builds may indicate engineering or unofficial firmware; this alone is not proof of compromise.",
            "Confirm firmware provenance and install official signed firmware if this build is unexpected.")
    elif tags != "Unknown":
        add("Platform Integrity", "Firmware signing tag", "PASS", "INFO",
            f"Build tags: {tags}.", "Build tags provide context but are not a cryptographic authenticity check.",
            "Verify firmware authenticity through the manufacturer's update mechanism.")
    else:
        add("Platform Integrity", "Firmware signing tag", "NOT TESTED", "INFO",
            "Build tags were unavailable.", "Firmware provenance cannot be inferred.",
            "Verify firmware through the OEM's official update channel.")

    # ADB and wireless debugging exposure
    rc, adb_enabled, _ = query("settings get global adb_enabled")
    if adb_enabled == "1":
        add("USB / Debugging", "USB debugging enabled", "WARNING", "MEDIUM",
            "Global ADB setting reports enabled.",
            "An authorized host can use ADB while debugging remains enabled.",
            "Disable USB debugging after this assessment and revoke unused host authorizations.")
    elif adb_enabled == "0":
        add("USB / Debugging", "USB debugging enabled", "PASS", "INFO",
            "Global ADB setting reports disabled (the current session may be unavailable after disconnect).",
            "Disabling ADB reduces the debugging attack surface.",
            "Keep USB debugging disabled when not actively required.")
    else:
        add("USB / Debugging", "USB debugging state", "NOT TESTED", "INFO",
            f"ADB setting returned {adb_enabled!r}.", "The setting could not be verified.",
            "Review Developer Options manually.")

    rc, wireless_port, _ = query("getprop service.adb.tcp.port")
    rc2, wireless_enabled, _ = query("settings get global adb_wifi_enabled")
    if (wireless_port not in ("", "0", "Unknown")) or wireless_enabled == "1":
        add("USB / Debugging", "Wireless ADB exposure", "WARNING", "MEDIUM",
            f"Wireless debugging indicators: tcp_port={wireless_port}, adb_wifi_enabled={wireless_enabled}.",
            "Wireless debugging can expose ADB over a network to paired or authorized clients.",
            "Turn off Wireless debugging in Developer Options when not in use; remove unneeded paired devices.")
    elif rc == 0 or rc2 == 0:
        add("USB / Debugging", "Wireless ADB exposure", "PASS", "INFO",
            "No active wireless ADB indicator was returned by the queried properties/settings.",
            "This is a limited indicator and does not scan the network for ADB services.",
            "Keep Wireless debugging disabled unless needed.")
    else:
        add("USB / Debugging", "Wireless ADB exposure", "NOT TESTED", "INFO",
            "Wireless ADB settings were not readable.", "Wireless debugging exposure is unknown.",
            "Review Developer Options > Wireless debugging.")

    # Legacy unknown-source setting (not authoritative on modern Android)
    rc, sideload, _ = query("settings get secure install_non_market_apps")
    add("Application Security", "Legacy unknown-source install setting",
        "WARNING" if sideload == "1" else "NOT TESTED", "MEDIUM" if sideload == "1" else "INFO",
        f"Legacy install_non_market_apps value: {sideload}. Modern Android uses per-source permissions, so this is not a complete sideloading check.",
        "Installing untrusted APKs can introduce malicious or vulnerable applications.",
        "Review Settings > Apps > Special app access > Install unknown apps and disable access for browsers/file managers that do not need it.")

    # App inventory + sensitive permission exposure (permission grants are signals, not proof of a vulnerability)
    rc, packages, err = query("pm list packages -3", 8)
    third_party = [line.split(":", 1)[1].strip() for line in packages.splitlines()
                   if line.startswith("package:")]
    if rc == 0:
        add("Application Inventory", "Third-party application inventory", "PASS", "INFO",
            f"ADB returned {len(third_party)} third-party package identifiers. No APK code or private app data was extracted.",
            "Unused, outdated, or sideloaded apps can increase the device attack surface.",
            "Remove apps you do not use and update remaining apps through trusted stores.")
        sensitive = {
            "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS", "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG", "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_PHONE_STATE", "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.MANAGE_EXTERNAL_STORAGE", "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.BIND_ACCESSIBILITY_SERVICE"
        }
        exposed = []
        # Keep the audit bounded: inspect at most 20 third-party package dumps.
        for package in third_party[:20]:
            prc, dump, _ = query(f"dumpsys package {package}", 1)
            if prc != 0:
                continue
            granted = []
            for line in dump.splitlines():
                line = line.strip()
                for perm in sensitive:
                    if perm in line and ("granted=true" in line.lower() or "granted: true" in line.lower()):
                        granted.append(perm)
            if granted:
                exposed.append((package, sorted(set(granted))))
        if exposed:
            summary = "; ".join(f"{pkg}: {', '.join(perms[:5])}" for pkg, perms in exposed[:12])
            add("Application Security", "Sensitive permissions granted to third-party apps", "WARNING", "LOW",
                f"{len(exposed)} of up to {min(20, len(third_party))} inspected apps showed one or more sensitive permission indicators. Examples: {summary}",
                "Sensitive permissions can expose messages, contacts, microphone, camera, location, or overlay capability. A legitimate permission grant is not automatically a vulnerability.",
                "Review each listed app's purpose and revoke permissions it does not genuinely need. Check Accessibility and special app access separately in Android Settings.")
        else:
            add("Application Security", "Sensitive permission exposure sample", "NOT TESTED", "INFO",
                f"No matching granted-permission indicators were parsed from up to {min(20, len(third_party))} app package dumps. OEM output may differ.",
                "This is not proof that apps have no sensitive access; special app access and runtime permissions may be represented differently.",
                "Review Permission Manager, Accessibility, Notification access, Display over other apps, and Install unknown apps manually.")
    else:
        add("Application Inventory", "Third-party application inventory", "NOT TESTED", "INFO",
            f"Package inventory query failed: {err or packages}.", "Installed app exposure could not be assessed.",
            "Review installed applications and permissions manually.")

    # Device administration and lock-screen hints
    rc, admins, _ = query("dumpsys device_policy", 5)
    if rc == 0:
        active_admin_lines = [line.strip() for line in admins.splitlines()
                              if "admin=" in line.lower() or "device owner" in line.lower()]
        add("Device Management", "Device administrator / owner configuration", "NOT TESTED", "INFO",
            ("Device policy service responded; relevant entries: " + "; ".join(active_admin_lines[:8]))
            if active_admin_lines else "Device policy service responded, but active-admin state was not confidently parsed.",
            "Unexpected device administrators or management owners can enforce policies or control device settings.",
            "Review Settings > Security > Device admin apps and Settings > Passwords & accounts / Work profile. Do not remove legitimate employer/school management.")
    else:
        add("Device Management", "Device administrator / owner configuration", "NOT TESTED", "INFO",
            "Device policy service could not be queried.", "Management configuration is unknown.",
            "Review Device admin apps and work-profile management settings manually.")

    # Network posture signals; no intrusive network scan
    rc, wifi_state, _ = query("cmd wifi status", 4)
    if rc == 0 and wifi_state:
        add("Network Posture", "Wi-Fi connection status", "PASS", "INFO",
            f"Device Wi-Fi service returned status: {wifi_state[:700]}",
            "This does not validate the security of the access point, encryption mode, or internet-facing services.",
            "Use trusted WPA2-AES/WPA3 networks, avoid open Wi-Fi for sensitive work, and keep router firmware updated.")
    else:
        add("Network Posture", "Wi-Fi connection status", "NOT TESTED", "INFO",
            "Wi-Fi status was not available through this Android build's ADB interface.",
            "Network security cannot be determined from this check.",
            "Review the connected network and router security settings manually.")

    # Lock credential cannot be inspected; explicitly avoid guessing.
    rc, lock_disabled, _ = query("settings get secure lockscreen.disabled")
    if rc == 0 and lock_disabled == "1":
        add("Access Control", "Lock-screen disabled indicator", "FAIL", "HIGH",
            "The secure setting reports lockscreen.disabled=1.",
            "A device without a secure lock screen is at increased risk if lost or unattended.",
            "Set a strong PIN/password and configure a short auto-lock period.")
    else:
        add("Access Control", "Screen-lock strength", "NOT TESTED", "INFO",
            "ADB cannot reliably establish credential strength, biometric enrollment, or auto-lock policy on all OEM builds.",
            "A weak or absent screen lock can expose personal and work data.",
            "Manually verify a strong PIN/password, biometrics, and a short auto-lock timeout.")

    add("Scope", "Exploit / CVE validation", "NOT TESTED", "INFO",
        "No exploit attempts or live CVE matching were performed. This tool does not currently query a maintained vendor/CVE feed.",
        "A posture audit can miss application-specific, firmware-specific, and remotely exploitable vulnerabilities.",
        "For deeper assurance, correlate the exact model, build fingerprint, patch level, and app versions with current vendor bulletins and a qualified mobile security assessment.")
    return findings

def assess_ios(device: Device, emit):
    findings = []
    def add(cat, title, status, sev, details, impact, rec):
        findings.append(Finding(cat, title, status, sev, details, impact, rec))
        emit(findings[-1])
    add("Connection", "Trusted iOS device detected", "PASS", "INFO",
        "The device was listed by libimobiledevice. Pairing/trust may be required.",
        "A trusted host can access limited device metadata.",
        "Unpair/revoke trust for computers you no longer use.")
    add("OS updates", "iOS version recorded", "NOT TESTED", "INFO",
        f"Detected version: {device.os_version}. This utility does not maintain an Apple vulnerability database.",
        "An outdated iOS release may lack important security fixes.",
        "Install the latest iOS version supported by the device via Settings > General > Software Update.")
    add("Data protection", "Device encryption", "NOT TESTED", "INFO",
        "iOS data protection cannot be fully audited through this USB interface.",
        "Data protection depends on passcode and device security configuration.",
        "Use a strong alphanumeric passcode and keep the device updated.")
    add("Access control", "Passcode and biometric policy", "NOT TESTED", "INFO",
        "Passcode strength, Face ID/Touch ID configuration, and auto-lock are not exposed here.",
        "Weak access controls can expose personal information.",
        "Review Face ID/Touch ID & Passcode settings and use a strong passcode.")
    add("Boot integrity", "Jailbreak / system integrity", "NOT TESTED", "INFO",
        "This tool does not perform jailbreak detection or forensic integrity validation.",
        "A modified device may have a larger attack surface.",
        "If compromise is suspected, seek a qualified mobile-forensics examination.")
    add("Applications", "Installed app security review", "NOT TESTED", "INFO",
        "iOS restricts third-party app inventory and security inspection over USB.",
        "Outdated or over-privileged apps may create privacy and security risks.",
        "Update apps, remove unused apps, and review app privacy permissions.")
    add("Network", "Network and exposed services", "NOT TESTED", "INFO",
        "Network security checks require a separate authorized network assessment.",
        "Unsafe Wi-Fi or exposed services may create risk.",
        "Use trusted Wi-Fi, disable unnecessary sharing, and avoid unknown configuration profiles.")
    add("Profiles", "Configuration profiles / MDM", "NOT TESTED", "INFO",
        "Profiles and MDM configuration are not comprehensively inspected by this utility.",
        "An untrusted profile may alter network, certificate, or management settings.",
        "Review Settings > General > VPN & Device Management and remove only profiles you recognize as unwanted.")
    return findings

def score_findings(findings):
    # Score is a heuristic triage indicator, not a certification or compromise probability.
    penalties = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
    score = 100
    for f in findings:
        if f.status == "FAIL":
            score -= penalties.get(f.severity, 5)
        elif f.status == "WARNING":
            score -= max(2, penalties.get(f.severity, 4) // 2)
    return max(0, min(100, score))

def generate_pdf(device, findings, output_path, duration):
    """Create a styled, multi-section security assessment PDF."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                        TableStyle, PageBreak, KeepTogether)
        from xml.sax.saxutils import escape
    except ImportError:
        raise RuntimeError("PDF export requires reportlab. Install it with: python3 -m pip install reportlab")

    score = score_findings(findings)
    counts = {k: sum(1 for f in findings if f.status == k)
              for k in ("PASS", "FAIL", "WARNING", "NOT TESTED")}
    critical = sum(1 for f in findings if f.severity == "CRITICAL" and f.status in ("FAIL", "WARNING"))
    high = sum(1 for f in findings if f.severity == "HIGH" and f.status in ("FAIL", "WARNING"))
    medium = sum(1 for f in findings if f.severity == "MEDIUM" and f.status in ("FAIL", "WARNING"))
    low = sum(1 for f in findings if f.severity == "LOW" and f.status in ("FAIL", "WARNING"))

    navy = colors.HexColor("#101D33")
    blue = colors.HexColor("#176B87")
    cyan = colors.HexColor("#21B6C7")
    pale = colors.HexColor("#EEF4F8")
    ink = colors.HexColor("#172638")
    muted = colors.HexColor("#607286")
    red = colors.HexColor("#B42336")
    amber = colors.HexColor("#A15C00")
    green = colors.HexColor("#147D55")
    purple = colors.HexColor("#6551A3")
    border = colors.HexColor("#D8E1E9")

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold",
        fontSize=23, leading=27, textColor=colors.white, alignment=0, spaceAfter=4))
    styles.add(ParagraphStyle(name="SubtitleWhite", parent=styles["Normal"], fontSize=9,
        leading=13, textColor=colors.HexColor("#D6E6F1")))
    styles.add(ParagraphStyle(name="SectionX", parent=styles["Heading2"], fontName="Helvetica-Bold",
        fontSize=13, leading=16, textColor=navy, spaceBefore=9, spaceAfter=7))
    styles.add(ParagraphStyle(name="BodyX", parent=styles["BodyText"], fontSize=8.5,
        leading=12, textColor=ink, spaceAfter=3))
    styles.add(ParagraphStyle(name="SmallX", parent=styles["BodyText"], fontSize=7.4,
        leading=10, textColor=muted))
    styles.add(ParagraphStyle(name="FindingTitleX", parent=styles["BodyText"], fontName="Helvetica-Bold",
        fontSize=9, leading=12, textColor=navy))
    styles.add(ParagraphStyle(name="LabelX", parent=styles["BodyText"], fontName="Helvetica-Bold",
        fontSize=7, leading=9, textColor=muted))
    styles.add(ParagraphStyle(name="WhiteMetric", parent=styles["BodyText"], fontName="Helvetica-Bold",
        fontSize=16, leading=18, textColor=navy, alignment=1))
    styles.add(ParagraphStyle(name="WhiteMetricLabel", parent=styles["BodyText"], fontSize=6.8,
        leading=8, textColor=muted, alignment=1))

    def P(value, style="BodyX"):
        return Paragraph(escape(str(value)).replace("\n", "<br/>"), styles[style])

    def on_page(canvas, doc):
        canvas.saveState()
        w, h = A4
        if doc.page > 1:
            canvas.setFillColor(navy)
            canvas.rect(0, h - 10*mm, w, 10*mm, fill=1, stroke=0)
            canvas.setFillColor(colors.white)
            canvas.setFont("Helvetica-Bold", 7)
            canvas.drawString(18*mm, h - 6.5*mm, "MOBILE SECURITY INSPECTOR")
            canvas.setFillColor(muted)
            canvas.setFont("Helvetica", 7)
            canvas.drawString(18*mm, 10*mm, "CONFIDENTIAL  |  AUTHORIZED DEVICE ASSESSMENT")
            canvas.drawRightString(w - 18*mm, 10*mm, f"Page {doc.page}")
            canvas.setStrokeColor(border)
            canvas.line(18*mm, 14*mm, w-18*mm, 14*mm)
        canvas.restoreState()

    doc = SimpleDocTemplate(str(output_path), pagesize=A4, rightMargin=18*mm,
        leftMargin=18*mm, topMargin=18*mm, bottomMargin=19*mm,
        title="Mobile Device Security Assessment", author="Mobile Security Inspector")
    story = []

    # Cover banner
    cover = Table([[[
        Paragraph("MOBILE DEVICE", styles["ReportTitle"]),
        Paragraph("SECURITY ASSESSMENT", styles["ReportTitle"]),
        Spacer(1, 3*mm),
        Paragraph("CONFIDENTIAL TECHNICAL REPORT  |  READ-ONLY DEVICE AUDIT", styles["SubtitleWhite"])
    ]]], colWidths=[174*mm], rowHeights=[42*mm])
    cover.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),navy), ("BOX",(0,0),(-1,-1),0,navy),
        ("LEFTPADDING",(0,0),(-1,-1),10*mm), ("RIGHTPADDING",(0,0),(-1,-1),8*mm),
        ("TOPPADDING",(0,0),(-1,-1),7*mm), ("BOTTOMPADDING",(0,0),(-1,-1),5*mm),
    ]))
    story += [cover, Spacer(1, 7*mm)]

    meta = [
        [P("DEVICE", "LabelX"), P("PLATFORM", "LabelX"), P("ASSESSMENT DATE", "LabelX")],
        [P(device.model), P(device.platform), P(datetime.now().strftime("%d %B %Y, %H:%M"))],
        [P("OS VERSION", "LabelX"), P("DEVICE IDENTIFIER", "LabelX"), P("ASSESSMENT DURATION", "LabelX")],
        [P(device.os_version), P(device.identifier), P(f"{duration:.1f} seconds")]
    ]
    mt = Table(meta, colWidths=[58*mm, 58*mm, 58*mm])
    mt.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),pale), ("GRID",(0,0),(-1,-1),0.45,border),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"), ("LEFTPADDING",(0,0),(-1,-1),7),
        ("RIGHTPADDING",(0,0),(-1,-1),7), ("TOPPADDING",(0,0),(-1,-1),6),
        ("BOTTOMPADDING",(0,0),(-1,-1),6)
    ]))
    story += [mt, P("EXECUTIVE SUMMARY", "SectionX")]

    score_color = green if score >= 85 else amber if score >= 65 else red
    metric_cells = [
        [P(f"{score}/100", "WhiteMetric"), P(str(counts["PASS"]), "WhiteMetric"),
         P(str(counts["FAIL"] + counts["WARNING"]), "WhiteMetric"), P(str(counts["NOT TESTED"]), "WhiteMetric")],
        [P("BASELINE SCORE", "WhiteMetricLabel"), P("PASSED", "WhiteMetricLabel"),
         P("ISSUES / WARNINGS", "WhiteMetricLabel"), P("NOT TESTED", "WhiteMetricLabel")]
    ]
    metrics = Table(metric_cells, colWidths=[43.5*mm]*4, rowHeights=[12*mm, 8*mm])
    metrics.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#E5F3F0")),
        ("BACKGROUND",(1,0),(1,-1),colors.HexColor("#EAF6F0")),
        ("BACKGROUND",(2,0),(2,-1),colors.HexColor("#FFF0EF")),
        ("BACKGROUND",(3,0),(3,-1),colors.HexColor("#FFF6E5")),
        ("BOX",(0,0),(-1,-1),0.5,border), ("INNERGRID",(0,0),(-1,-1),0.5,border),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"), ("TOPPADDING",(0,0),(-1,-1),4),
        ("BOTTOMPADDING",(0,0),(-1,-1),4)
    ]))
    story += [metrics, Spacer(1, 3*mm),
        P(f"Risk counts: Critical {critical}  |  High {high}  |  Medium {medium}  |  Low {low}", "SmallX"),
        Spacer(1, 2*mm),
        P("The baseline score is a heuristic summary of checks completed by this tool. It is not a certification, "
          "a probability of compromise, or proof that the device is secure. NOT TESTED means the check could not "
          "be verified and is not counted as a pass.", "SmallX")]

    story.append(P("DEVICE INFORMATION", "SectionX"))
    device_rows = [
        ["Manufacturer", device.manufacturer], ["Model", device.model], ["Platform", device.platform],
        ["OS version", device.os_version], ["Build", device.build], ["Device identifier", device.identifier],
        ["Connection", device.connection], ["Serial", device.serial]
    ]
    dt = Table([[P(k, "LabelX"), P(v)] for k,v in device_rows], colWidths=[43*mm, 131*mm])
    dt.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(0,-1),pale), ("GRID",(0,0),(-1,-1),0.4,border),
        ("VALIGN",(0,0),(-1,-1),"TOP"), ("LEFTPADDING",(0,0),(-1,-1),7),
        ("TOPPADDING",(0,0),(-1,-1),5), ("BOTTOMPADDING",(0,0),(-1,-1),5)
    ]))
    story.append(dt)

    story.append(P("ASSESSMENT SCOPE", "SectionX"))
    story.append(P("This assessment uses the interfaces exposed by the connected device. Android checks use ADB and "
        "read-only system queries. Some checks are OEM/version dependent. The audit does not exploit the device, "
        "bypass authentication, extract private user files, or modify device settings.", "BodyX"))
    story.append(PageBreak())

    story.append(P("DETAILED TEST RESULTS", "SectionX"))
    story.append(P("Each check is classified by its observed result. A warning or failure should be reviewed in context; "
        "a permission grant or unlocked development feature is not automatically a confirmed vulnerability.", "SmallX"))
    status_colors = {"PASS": green, "FAIL": red, "WARNING": amber, "NOT TESTED": muted}
    for index, f in enumerate(findings, 1):
        title_line = Table([[
            P(f"{index:02d}  {f.title}", "FindingTitleX"),
            Paragraph(f"<font color='{status_colors.get(f.status, muted).hexval()}'><b>{escape(f.status)} / {escape(f.severity)}</b></font>",
                      styles["SmallX"])
        ]], colWidths=[130*mm, 44*mm])
        title_line.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),pale), ("BOX",(0,0),(-1,-1),0.5,border),
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"), ("LEFTPADDING",(0,0),(-1,-1),7),
            ("RIGHTPADDING",(0,0),(-1,-1),7), ("TOPPADDING",(0,0),(-1,-1),6),
            ("BOTTOMPADDING",(0,0),(-1,-1),6)
        ]))
        detail = Table([
            [P("CATEGORY", "LabelX"), P(f.category)],
            [P("OBSERVATION", "LabelX"), P(f.details)],
            [P("POTENTIAL IMPACT", "LabelX"), P(f.impact)],
            [P("RECOMMENDED ACTION", "LabelX"), P(f.recommendation)]
        ], colWidths=[36*mm, 138*mm])
        detail.setStyle(TableStyle([
            ("GRID",(0,0),(-1,-1),0.35,border), ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#F7F9FB")),
            ("VALIGN",(0,0),(-1,-1),"TOP"), ("LEFTPADDING",(0,0),(-1,-1),6),
            ("RIGHTPADDING",(0,0),(-1,-1),6), ("TOPPADDING",(0,0),(-1,-1),5),
            ("BOTTOMPADDING",(0,0),(-1,-1),5)
        ]))
        story.append(KeepTogether([title_line, detail, Spacer(1, 3*mm)]))

    story.append(PageBreak())
    story.append(P("REMEDIATION PLAN", "SectionX"))
    story.append(P("Prioritize confirmed FAIL results first, then HIGH/MEDIUM warnings. Validate every recommendation "
        "against the exact device model, region, firmware and ownership/management policy before applying changes.", "BodyX"))
    prioritized = [f for f in findings if f.status in ("FAIL", "WARNING", "NOT TESTED")]
    if not prioritized:
        story.append(P("No remediation items were generated from the checks that ran. This does not establish that the device is vulnerability-free.", "BodyX"))
    for i, f in enumerate(prioritized, 1):
        story.append(KeepTogether([
            P(f"{i}. {f.title}  [{f.status} / {f.severity}]", "FindingTitleX"),
            P(f.recommendation, "BodyX"), Spacer(1, 2*mm)
        ]))

    story.append(P("LIMITATIONS & PROFESSIONAL USE", "SectionX"))
    story.append(P("This utility is a baseline posture scanner, not a full mobile application security assessment, "
        "mobile forensic examination, malware analysis engine, or live CVE scanner. It cannot inspect all protected "
        "Android internals, app private data, kernel state, radio/baseband firmware, cloud account security, or every "
        "OEM-specific setting. It does not currently perform dynamic app testing, network penetration testing, "
        "certificate pinning analysis, exploit validation, or comprehensive CVE correlation. For high-assurance "
        "work, combine this report with current Android Security Bulletins, vendor advisories, application testing, "
        "and a qualified mobile security assessment.", "SmallX"))
    story.append(Spacer(1, 4*mm))
    story.append(P("END OF REPORT", "LabelX"))

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)

def connection_diagnostics():
    adb = find_tool("adb")
    idevice = find_tool("idevice_id")
    lines = [f"Operating system: {platform.platform()}",
             f"Python: {platform.python_version()}",
             f"ADB executable: {adb or 'NOT FOUND'}",
             f"idevice_id executable: {idevice or 'NOT FOUND'}"]
    if adb:
        rc, out, err = run_cmd([adb, "version"], 6)
        lines += ["", "ADB VERSION:", out or err or f"Command exit code: {rc}"]
        run_cmd([adb, "start-server"], 8)
        rc, out, err = run_cmd([adb, "devices", "-l"], 8)
        lines += ["", "ADB DEVICE LIST:", out or "(no devices listed)", err]
    else:
        lines += ["", "ADB SETUP:", "Install Android Platform Tools: brew install android-platform-tools",
                  "Then run: adb kill-server && adb start-server && adb devices -l"]
    lines += ["", "ANDROID PHONE CHECKLIST:",
              "1. Unlock the phone and keep its screen on.",
              "2. Use a USB data cable (some cables only charge).",
              "3. Enable Developer options > USB debugging.",
              "4. Set USB mode to File Transfer / Android Auto if offered.",
              "5. Accept the 'Allow USB debugging?' RSA prompt on the phone.",
              "6. In this app, click Detect / Refresh Devices."]
    return "\\n".join(x for x in lines if x is not None)

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1180x780")
        self.minsize(980, 680)
        self.configure(bg=BG)
        self.events = queue.Queue()
        self.device = None
        self.findings = []
        self.last_report = None
        self.last_duration = 0.0
        self.scan_running = False
        self._style()
        self._build()
        self.after(150, self._drain_events)
        self.refresh_devices()

    def _style(self):
        st = ttk.Style(self)
        st.theme_use("clam")
        st.configure("TCombobox", fieldbackground=PANEL2, background=PANEL2, foreground=TEXT, arrowcolor=CYAN)
        st.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=TEXT, rowheight=28, borderwidth=0)
        st.configure("Treeview.Heading", background=PANEL2, foreground=CYAN, font=("Segoe UI", 9, "bold"))
        st.map("Treeview", background=[("selected", "#17465A")])
        st.configure("Horizontal.TProgressbar", troughcolor=PANEL2, background=CYAN, bordercolor=PANEL2, lightcolor=CYAN, darkcolor=CYAN)

    def _button(self, parent, label, command, color=CYAN):
        return tk.Button(parent, text=label, command=command, bg="#123044" if color==CYAN else "#173629",
            fg=color, activebackground="#1B4057", activeforeground="white", relief="flat",
            font=("Segoe UI", 10, "bold"), padx=14, pady=9, cursor="hand2")

    def _build(self):
        self.geometry("1240x780")
        self.minsize(1040, 680)
        self.configure(bg=BG)

        # Animated cyber header
        self.hero = tk.Canvas(self, height=112, bg="#091321", highlightthickness=0)
        self.hero.pack(fill="x", padx=18, pady=(14, 8))
        self.hero.create_text(28, 35, anchor="w", text="◈  MOBILE SECURITY INSPECTOR",
                             fill=CYAN, font=("Segoe UI", 21, "bold"), tags="hero_title")
        self.hero.create_text(30, 72, anchor="w",
                             text="ADVANCED DEVICE POSTURE ANALYSIS  /  ANDROID • iOS • USB",
                             fill="#91A9C2", font=("Consolas", 9), tags="hero_sub")
        self.hero.create_text(1310, 34, anchor="e", text="SYSTEM STATUS  ● ONLINE",
                             fill=GREEN, font=("Consolas", 9, "bold"), tags="hero_status")
        self.hero.create_line(24, 101, 1335, 101, fill="#16465B", width=1)
        self.particles = []
        import random
        for _ in range(38):
            x=random.randint(0, 1350); y=random.randint(0, 105)
            r=random.choice([1, 1, 2])
            item=self.hero.create_oval(x-r,y-r,x+r,y+r,fill=random.choice([CYAN,"#236C86","#3A5B85"]),outline="")
            self.particles.append((item, random.choice([-1,1]), random.choice([1,2])))
        self._animate_header()

        shell=tk.Frame(self,bg=BG); shell.pack(fill="both",expand=True,padx=18,pady=(0,10))
        sidebar=tk.Frame(shell,bg="#0D1726",width=292,highlightbackground="#1C344B",highlightthickness=1)
        sidebar.pack(side="left",fill="y",padx=(0,14)); sidebar.pack_propagate(False)
        main=tk.Frame(shell,bg=BG); main.pack(side="left",fill="both",expand=True)

        # Persistent report actions stay visible even when the window is not maximized.
        report_bar=tk.Frame(main,bg="#102238",highlightbackground="#24516A",highlightthickness=1)
        report_bar.pack(side="bottom",fill="x",pady=(9,0))
        tk.Label(report_bar,text="REPORT CENTER",bg="#102238",fg=CYAN,
                 font=("Consolas",9,"bold")).pack(side="left",padx=12,pady=10)
        self.report_status=tk.Label(report_bar,text="Complete an assessment to generate a report",
                 bg="#102238",fg=MUTED,font=("Segoe UI",8))
        self.report_status.pack(side="left",padx=8)
        self._button(report_bar,"GENERATE PDF REPORT",self.export_report,GREEN).pack(side="right",padx=7,pady=6)
        self._button(report_bar,"UPLOAD REPORT",self.upload_report,PURPLE).pack(side="right",padx=7,pady=6)

        self._section(sidebar,"01  DEVICE CONNECTION")
        self.device_var=tk.StringVar()
        self.device_combo=ttk.Combobox(sidebar,textvariable=self.device_var,state="readonly")
        self.device_combo.pack(fill="x",padx=14,pady=(4,8),ipady=5)
        self._button(sidebar,"⟳  SCAN USB DEVICES",self.refresh_devices).pack(fill="x",padx=14,pady=4)
        self._button(sidebar,"IDENTIFY DEVICE",self.identify).pack(fill="x",padx=14,pady=4)
        self._button(sidebar,"USB / ADB DIAGNOSTICS",self.show_diagnostics,AMBER).pack(fill="x",padx=14,pady=4)
        self.status=tk.Label(sidebar,text="● Waiting for device",bg="#0D1726",fg=AMBER,font=("Segoe UI",9,"bold"))
        self.status.pack(anchor="w",padx=16,pady=(9,8))

        self._section(sidebar,"02  DEVICE INTELLIGENCE")
        self.profile=tk.Text(sidebar,height=10,bg="#07111E",fg="#CFE6F4",insertbackground=TEXT,
            relief="flat",font=("Consolas",8),padx=10,pady=10,wrap="word",
            highlightbackground="#1B344A",highlightthickness=1)
        self.profile.pack(fill="x",padx=14,pady=5)
        self.profile.insert("1.0","NO DEVICE IDENTIFIED\\n\\nConnect a phone using a data-capable USB cable, unlock it, and authorize this computer.")
        self.profile.configure(state="disabled")

        self._section(sidebar,"03  TOOLCHAIN")
        self._button(sidebar,"⬇  INSTALL / UPDATE TOOLS",self.install_tools,PURPLE).pack(fill="x",padx=14,pady=5)
        self.tool_status=tk.Label(sidebar,text="ADB + PDF libraries",bg="#0D1726",fg=MUTED,font=("Segoe UI",8))
        self.tool_status.pack(anchor="w",padx=16,pady=(0,8))

        self._section(sidebar,"04  SECURITY OPERATIONS")
        self._button(sidebar,"▶  START DEEP AUDIT",self.start_audit,GREEN).pack(fill="x",padx=14,pady=4)
        self.progress=ttk.Progressbar(sidebar,mode="determinate",maximum=100)
        self.progress.pack(fill="x",padx=14,pady=(10,4))
        self.progress_label=tk.Label(sidebar,text="READY • waiting for assessment",bg="#0D1726",fg=MUTED,font=("Segoe UI",8))
        self.progress_label.pack(anchor="w",padx=14,pady=(0,8))
        self._button(sidebar,"GENERATE PDF REPORT",self.export_report).pack(fill="x",padx=14,pady=4)
        self._button(sidebar,"UPLOAD REPORT / REMEDIATION",self.upload_report,PURPLE).pack(fill="x",padx=14,pady=4)

        # Main dashboard title and animated status strip
        top=tk.Frame(main,bg=BG); top.pack(fill="x",pady=(0,10))
        tk.Label(top,text="SECURITY OPERATIONS CENTER",bg=BG,fg=TEXT,font=("Segoe UI",15,"bold")).pack(side="left")
        self.live_label=tk.Label(top,text="● LIVE MONITORING",bg=BG,fg=GREEN,font=("Consolas",9,"bold"))
        self.live_label.pack(side="right")
        self._animate_live_label()

        cards=tk.Frame(main,bg=BG); cards.pack(fill="x",pady=(0,10))
        self.score_card=self._metric(cards,"SECURITY POSTURE","--",CYAN)
        self.pass_card=self._metric(cards,"CHECKS PASSED","0",GREEN)
        self.issue_card=self._metric(cards,"FINDINGS","0",RED)
        self.untested_card=self._metric(cards,"NOT VERIFIED","0",AMBER)

        # Scan visual / progress card
        scan=tk.Frame(main,bg="#0E1B2D",highlightbackground="#1A3C53",highlightthickness=1)
        scan.pack(fill="x",pady=(0,10))
        scan_left=tk.Frame(scan,bg="#0E1B2D"); scan_left.pack(side="left",fill="both",expand=True,padx=14,pady=11)
        tk.Label(scan_left,text="ASSESSMENT ENGINE",bg="#0E1B2D",fg=CYAN,font=("Consolas",9,"bold")).pack(anchor="w")
        tk.Label(scan_left,text="Read-only device posture inspection",bg="#0E1B2D",fg=TEXT,font=("Segoe UI",11,"bold")).pack(anchor="w",pady=(4,2))
        tk.Label(scan_left,text="Checks available device interfaces; inaccessible controls remain NOT TESTED.",bg="#0E1B2D",fg=MUTED,font=("Segoe UI",8)).pack(anchor="w")
        self.scan_canvas=tk.Canvas(scan,width=116,height=82,bg="#0E1B2D",highlightthickness=0)
        self.scan_canvas.pack(side="right",padx=18,pady=4)
        self._draw_scan_radar()

        self._section(main,"SECURITY FINDINGS  /  SELECT A ROW FOR DETAILS")
        tablewrap=tk.Frame(main,bg="#0E1B2D",highlightbackground="#1A3C53",highlightthickness=1)
        tablewrap.pack(fill="both",expand=True,pady=(3,9))
        columns=("category","test","status","severity")
        self.table=ttk.Treeview(tablewrap,columns=columns,show="headings",height=12)
        for c,title,width in [("category","CATEGORY",145),("test","SECURITY CHECK",440),("status","RESULT",120),("severity","SEVERITY",110)]:
            self.table.heading(c,text=title); self.table.column(c,width=width,anchor="w")
        self.table.pack(fill="both",expand=True,padx=7,pady=7)
        self.table.bind("<<TreeviewSelect>>",self.show_finding)
        self.table.tag_configure("FAIL",foreground="#FF8292")
        self.table.tag_configure("WARNING",foreground="#F5C56A")
        self.table.tag_configure("PASS",foreground="#65DDAA")
        self.table.tag_configure("NOT TESTED",foreground="#A9B9CA")

        self._section(main,"INTELLIGENCE / IMPACT / REMEDIATION")
        self.details=tk.Text(main,height=7,bg="#0D1726",fg="#D8E7F2",relief="flat",
            font=("Segoe UI",9),padx=12,pady=10,wrap="word",
            highlightbackground="#1A3C53",highlightthickness=1)
        self.details.pack(fill="x")
        self.details.insert("1.0","Select a finding to view its evidence, potential impact, and recommended remediation.")
        self.details.configure(state="disabled")

        footer=tk.Label(self,text="AUTHORIZED DEVICE TESTING ONLY  •  READ-ONLY AUDIT  •  NOT TESTED ≠ PASS",
                        bg=BG,fg="#607B95",font=("Consolas",8))
        footer.pack(side="bottom",pady=(0,7))

    def _animate_header(self):
        if not self.winfo_exists():
            return
        width=max(self.hero.winfo_width(),1200)
        for item, direction, speed in self.particles:
            self.hero.move(item,direction*speed,0)
            x1,y1,x2,y2=self.hero.coords(item)
            if x1>width: self.hero.move(item,-width-5,0)
            elif x2<0: self.hero.move(item,width+5,0)
        self.after(65,self._animate_header)

    def _animate_live_label(self):
        if not self.winfo_exists(): return
        current=self.live_label.cget("fg")
        self.live_label.config(fg=CYAN if current==GREEN else GREEN)
        self.after(850,self._animate_live_label)

    def _draw_scan_radar(self):
        c=self.scan_canvas
        c.delete("all")
        cx,cy=58,41
        for r in (13,25,37):
            c.create_oval(cx-r,cy-r,cx+r,cy+r,outline="#24516A")
        c.create_line(cx-43,cy,cx+43,cy,fill="#1B425B")
        c.create_line(cx,cy-38,cx,cy+38,fill="#1B425B")
        self.radar_angle=0
        self._animate_radar()

    def _animate_radar(self):
        if not self.winfo_exists(): return
        c=self.scan_canvas
        c.delete("sweep")
        import math
        self.radar_angle=(self.radar_angle+7)%360
        a=math.radians(self.radar_angle)
        x=58+37*math.cos(a); y=41+37*math.sin(a)
        c.create_line(58,41,x,y,fill=CYAN,width=2,tags="sweep")
        c.create_oval(54,37,62,45,fill=GREEN,outline="",tags="sweep")
        self.after(65,self._animate_radar)

    def _section(self, parent, title):
        tk.Label(parent, text=title, bg=parent["bg"], fg=CYAN, font=("Segoe UI",9,"bold")).pack(anchor="w", padx=15, pady=(14,3))

    def _metric(self, parent, label, value, color):
        f=tk.Frame(parent,bg=PANEL,padx=14,pady=12); f.pack(side="left",fill="x",expand=True,padx=(0,8))
        tk.Label(f,text=label,bg=PANEL,fg=MUTED,font=("Segoe UI",8,"bold")).pack(anchor="w")
        v=tk.Label(f,text=value,bg=PANEL,fg=color,font=("Segoe UI",21,"bold")); v.pack(anchor="w")
        return v

    def refresh_devices(self):
        found=[]
        for serial,state,line in adb_devices():
            found.append((f"Android  |  {serial}  |  {state}", "Android", serial, state))
        for udid in detect_ios():
            found.append((f"iOS  |  {udid}", "iOS", udid, "detected"))
        self.detected = found
        self.device_combo["values"]=[x[0] for x in found]
        if found:
            self.device_combo.current(0)
            self.status.config(text=f"● {len(found)} device(s) detected",fg=GREEN)
        else:
            self.device_var.set("")
            if not find_tool("adb"):
                self.status.config(text="● ADB not found — install Platform Tools",fg=RED)
                self.log_detail("ADB was not found. Click INSTALL / UPDATE TOOLS to install Google's Platform Tools automatically, or use the official Google download. Then refresh devices.")
            else:
                self.status.config(text="● No authorized Android device detected",fg=AMBER)
                self.log_detail("ADB is installed, but no phone is listed. Unlock the phone, enable USB debugging, use a data cable, accept the RSA authorization prompt, then refresh. Open USB / ADB TROUBLESHOOTING for live ADB output.")

    def log_detail(self, msg):
        self.details.configure(state="normal"); self.details.delete("1.0","end"); self.details.insert("1.0",msg); self.details.configure(state="disabled")

    def selected(self):
        idx=self.device_combo.current()
        return self.detected[idx] if idx>=0 and idx<len(getattr(self,"detected",[])) else None

    def show_diagnostics(self):
        win = tk.Toplevel(self)
        win.title("USB / ADB CONNECTION DIAGNOSTICS")
        win.geometry("760x590")
        win.configure(bg=BG)
        tk.Label(win, text="USB / ADB CONNECTION DIAGNOSTICS", bg=BG, fg=CYAN,
                 font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=18, pady=15)
        view = tk.Text(win, bg=PANEL, fg=TEXT, insertbackground=TEXT, relief="flat",
                       font=("Consolas", 9), wrap="word", padx=12, pady=12)
        view.pack(fill="both", expand=True, padx=18, pady=(0,12))
        view.insert("1.0", connection_diagnostics())
        view.configure(state="disabled")
        actions = tk.Frame(win, bg=BG); actions.pack(fill="x", padx=18, pady=(0,15))
        tk.Button(actions, text="COPY TERMINAL COMMANDS", command=lambda: self.copy_diagnostics_commands(),
                  bg="#123044", fg=CYAN, relief="flat", padx=12, pady=8).pack(side="left")
        tk.Button(actions, text="REFRESH DEVICE LIST", command=lambda: (self.refresh_devices(), win.destroy()),
                  bg="#173629", fg=GREEN, relief="flat", padx=12, pady=8).pack(side="right")

    def copy_diagnostics_commands(self):
        commands = "~/Android/platform-tools/adb kill-server\\n~/Android/platform-tools/adb start-server\\n~/Android/platform-tools/adb devices -l"
        self.clipboard_clear()
        self.clipboard_append(commands)
        messagebox.showinfo("Copied", "Android setup and diagnostic commands copied to clipboard.")

    def install_tools(self):
        if getattr(self, "install_running", False):
            return
        self.install_running = True
        self.install_events = queue.Queue()
        win = tk.Toplevel(self)
        win.title("TOOLCHAIN INSTALLER")
        win.geometry("620x300")
        win.configure(bg=BG)
        win.transient(self)
        tk.Label(win, text="AUTOMATED TOOLCHAIN SETUP", bg=BG, fg=CYAN,
                 font=("Segoe UI", 15, "bold")).pack(anchor="w", padx=20, pady=(20, 8))
        tk.Label(win, text="Installs PDF libraries and Google's Android Platform Tools (ADB) on macOS.",
                 bg=BG, fg=TEXT, font=("Segoe UI", 9), wraplength=560,
                 justify="left").pack(anchor="w", padx=20)
        status = tk.Label(win, text="Preparing installer…", bg=BG, fg=MUTED,
                          font=("Consolas", 9))
        status.pack(anchor="w", padx=20, pady=(18, 7))
        bar = ttk.Progressbar(win, mode="indeterminate", length=560)
        bar.pack(padx=20, fill="x")
        bar.start(12)
        log = tk.Text(win, height=5, bg=PANEL, fg=TEXT, relief="flat",
                      font=("Consolas", 8), padx=9, pady=8)
        log.pack(fill="both", expand=True, padx=20, pady=12)
        log.insert("1.0", "Installer started. Internet access is required.")
        log.configure(state="disabled")

        def worker():
            messages = []
            try:
                proc = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--upgrade", "reportlab", "pypdf"],
                    capture_output=True, text=True, timeout=600
                )
                if proc.returncode != 0:
                    raise RuntimeError("Python library installation failed: " + (proc.stderr or proc.stdout)[-1600:])
                messages.append("PDF libraries installed successfully.")
                if platform.system() == "Darwin":
                    adb_path = Path.home() / "Android" / "platform-tools" / "adb"
                    existing = find_tool("adb")
                    if existing:
                        messages.append("ADB already detected: " + existing)
                    else:
                        self.install_events.put(("status", "Downloading official Google Platform Tools…"))
                        download_dir = Path.home() / "Downloads"
                        download_dir.mkdir(parents=True, exist_ok=True)
                        archive = download_dir / "platform-tools-latest-darwin.zip"
                        urllib.request.urlretrieve(
                            "https://dl.google.com/android/repository/platform-tools-latest-darwin.zip",
                            archive
                        )
                        self.install_events.put(("status", "Extracting ADB tools…"))
                        with zipfile.ZipFile(archive, "r") as zf:
                            zf.extractall(Path.home() / "Android")
                        if not adb_path.exists():
                            raise RuntimeError("ADB executable was not found in the downloaded Google archive.")
                        adb_path.chmod(0o755)
                        messages.append("ADB installed at " + str(adb_path))
                    profile = Path.home() / ".zprofile"
                    line = 'export PATH="$HOME/Android/platform-tools:$PATH"'
                    old = profile.read_text(errors="ignore") if profile.exists() else ""
                    if line not in old:
                        with profile.open("a") as f:
                            f.write("\n" + line + "\n")
                    messages.append("Added ~/Android/platform-tools to ~/.zprofile.")
                else:
                    messages.append("ADB auto-install is currently configured for macOS. Install Platform Tools separately for this operating system.")
                self.install_events.put(("done", (True, "\n".join(messages))))
            except Exception as exc:
                self.install_events.put(("done", (False, "\n".join(messages + [str(exc)]))))

        def poll():
            if not win.winfo_exists():
                return
            try:
                while True:
                    kind, payload = self.install_events.get_nowait()
                    if kind == "status":
                        status.config(text=payload)
                    elif kind == "done":
                        ok, report = payload
                        bar.stop()
                        self.install_running = False
                        status.config(text="Installation completed" if ok else "Installation needs attention",
                                      fg=GREEN if ok else RED)
                        log.configure(state="normal")
                        log.delete("1.0", "end")
                        log.insert("1.0", report)
                        log.configure(state="disabled")
                        self.tool_status.config(text="Toolchain ready" if ok else "Installation incomplete",
                                                fg=GREEN if ok else AMBER)
                        if ok:
                            self.refresh_devices()
                            messagebox.showinfo("Tools installed", report, parent=win)
                        else:
                            messagebox.showerror("Installer issue", report, parent=win)
                        return
            except queue.Empty:
                pass
            win.after(200, poll)

        threading.Thread(target=worker, daemon=True).start()
        win.after(200, poll)

    def identify(self):
        item=self.selected()
        if not item:
            messagebox.showwarning("No device","Connect a device and refresh the list first."); return
        _, kind, ident, state=item
        self.device = identify_android(ident) if kind=="Android" else identify_ios(ident)
        self.show_profile()
        self.status.config(text=f"● {kind} identified",fg=GREEN)
        if kind=="Android" and state!="device":
            messagebox.showinfo("Authorization required","Unlock the phone and accept the 'Allow USB debugging?' prompt. Then refresh devices.")

    def show_profile(self):
        d=self.device
        lines=[f"PLATFORM      {d.platform}",f"MODEL         {d.model}",f"MAKER         {d.manufacturer}",
               f"OS VERSION    {d.os_version}",f"BUILD         {d.build}",f"IDENTIFIER    {d.identifier}",
               f"SERIAL        {d.serial}",f"CONNECTION    {d.connection}"]
        if d.extra:
            lines += ["", "ADDITIONAL INFORMATION"]+[f"{k}: {v}" for k,v in d.extra.items()]
        self.profile.configure(state="normal"); self.profile.delete("1.0","end"); self.profile.insert("1.0","\n".join(lines)); self.profile.configure(state="disabled")

    def start_audit(self):
        if self.scan_running: return
        if not self.device:
            self.identify()
        if not self.device: return
        if self.device.platform=="Android":
            state=next((x[1] for x in adb_devices() if x[0]==self.device.identifier),"missing")
            if state!="device":
                messagebox.showerror("Device not authorized","ADB device state is not 'device'. Unlock it, authorize this computer, and try again."); return
        self.scan_running=True; self.findings=[]; self.progress["value"]=0
        for row in self.table.get_children(): self.table.delete(row)
        self.update_metrics()
        self.progress_label.config(text="Running checks…")
        if hasattr(self, "report_status"):
            self.report_status.config(text="Audit running • report will be available when complete", fg=AMBER)
        threading.Thread(target=self._audit_worker,daemon=True).start()

    def _audit_worker(self):
        start=time.monotonic()
        def emit(f): self.events.put(("finding",f))
        try:
            results=assess_android(self.device,emit) if self.device.platform=="Android" else assess_ios(self.device,emit)
            self.events.put(("complete",(results,time.monotonic()-start)))
        except Exception as e:
            self.events.put(("error",str(e)))

    def _drain_events(self):
        try:
            while True:
                kind,data=self.events.get_nowait()
                if kind=="finding":
                    self.findings.append(data)
                    self.table.insert("", "end", values=(data.category,data.title,data.status,data.severity), tags=(data.status,))
                    self.update_metrics()
                    self.progress["value"]=min(95, self.progress["value"]+8)
                elif kind=="complete":
                    self.findings,duration=data
                    self.last_duration = duration
                    self.scan_running=False; self.progress["value"]=100
                    self.progress_label.config(text=f"Completed in {duration:.1f}s • {len(self.findings)} checks")
                    if hasattr(self, "report_status"):
                        self.report_status.config(text=f"{len(self.findings)} checks ready • PDF report available", fg=GREEN)
                    self.update_metrics()
                    self.status.config(text="● Assessment completed",fg=GREEN)
                    messagebox.showinfo("Assessment completed",f"Device test completed.\n{len(self.findings)} checks recorded.\nGenerate the PDF report when ready.")
                elif kind=="error":
                    self.scan_running=False; self.progress_label.config(text="Assessment error")
                    messagebox.showerror("Assessment error",data)
        except queue.Empty:
            pass
        if self.scan_running:
            self.progress["value"]=min(90,self.progress["value"]+1)
        self.after(150,self._drain_events)

    def update_metrics(self):
        passed=sum(f.status=="PASS" for f in self.findings)
        issues=sum(f.status in ("FAIL","WARNING") for f in self.findings)
        untested=sum(f.status=="NOT TESTED" for f in self.findings)
        self.score_card.config(text=f"{score_findings(self.findings)}/100" if self.findings else "--")
        self.pass_card.config(text=str(passed)); self.issue_card.config(text=str(issues)); self.untested_card.config(text=str(untested))

    def show_finding(self, _event=None):
        sel=self.table.selection()
        if not sel:return
        idx=self.table.index(sel[0])
        if idx>=len(self.findings):return
        f=self.findings[idx]
        content=(f"{f.title}\n\nCategory: {f.category}\nResult: {f.status}   Severity: {f.severity}\n\n"
                 f"OBSERVATION\n{f.details}\n\nPOTENTIAL IMPACT\n{f.impact}\n\nRECOMMENDED FIX\n{f.recommendation}")
        self.log_detail(content)

    def export_report(self):
        if not self.device:
            messagebox.showwarning("Device not identified",
                "Connect your phone, select it, and click IDENTIFY DEVICE before generating a report.")
            return
        if not self.findings:
            messagebox.showwarning("Assessment not completed",
                "No security findings are available yet. Click START DEEP AUDIT and wait for the assessment to finish.")
            return
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Save Mobile Security Assessment Report",
            defaultextension=".pdf",
            initialfile=f"Mobile_Security_Report_{datetime.now():%Y%m%d_%H%M%S}.pdf",
            filetypes=[("PDF report", "*.pdf")]
        )
        if not path:
            return
        try:
            generate_pdf(self.device, self.findings, path, self.last_duration)
            if not Path(path).is_file() or Path(path).stat().st_size == 0:
                raise RuntimeError("The PDF writer returned without creating a valid report file.")
            self.last_report = path
            if hasattr(self, "report_status"):
                self.report_status.config(text=f"Report saved: {Path(path).name}", fg=GREEN)
            messagebox.showinfo("Report generated successfully",
                                f"Your professional PDF report has been created.\n\nSaved to:\n{path}",
                                parent=self)
        except ImportError as e:
            messagebox.showerror("PDF library missing",
                "Install the required PDF library using INSTALL / UPDATE TOOLS, then try again.\n\n"+str(e),
                parent=self)
        except Exception as e:
            messagebox.showerror("PDF export failed",
                f"The report could not be generated.\n\n{type(e).__name__}: {e}",
                parent=self)

    def upload_report(self):
        path=filedialog.askopenfilename(filetypes=[("PDF reports","*.pdf")])
        if not path:return
        try:
            from pypdf import PdfReader
            reader=PdfReader(path)
            content="\n".join((p.extract_text() or "") for p in reader.pages)
            if not content.strip(): raise ValueError("No selectable text found. Scanned PDFs need OCR, which is not built in.")
            self.show_remediation(path,content)
        except ImportError:
            messagebox.showerror("Missing dependency","Install PDF import support:\npython -m pip install pypdf")
        except Exception as e:
            messagebox.showerror("Could not read PDF",str(e))

    def show_remediation(self,path,content):
        win=tk.Toplevel(self); win.title("REPORT REMEDIATION CENTRE"); win.geometry("850x650"); win.configure(bg=BG)
        tk.Label(win,text="REPORT ANALYSIS / REMEDIATION GUIDANCE",bg=BG,fg=CYAN,font=("Segoe UI",15,"bold")).pack(anchor="w",padx=18,pady=16)
        tk.Label(win,text=f"Loaded: {Path(path).name}",bg=BG,fg=MUTED).pack(anchor="w",padx=18)
        box=tk.Text(win,bg=PANEL,fg=TEXT,wrap="word",font=("Segoe UI",10),relief="flat",padx=14,pady=12)
        box.pack(fill="both",expand=True,padx=18,pady=12)
        # Deliberately provide safe workflow guidance rather than executing arbitrary PDF instructions.
        box.insert("1.0",
            "REPORT LOADED SUCCESSFULLY\n\n"
            "This version extracts report text and provides a safe remediation workflow. "
            "It does not blindly execute commands or modify a phone based on uploaded PDF text.\n\n"
            "REMEDIATION WORKFLOW\n"
            "1. Review each finding and confirm it applies to the connected device.\n"
            "2. Back up important data before changing device security settings.\n"
            "3. Apply official OS and app updates from the device settings / trusted app store.\n"
            "4. Review passcode, lock-screen, app permissions, profiles, and USB debugging manually.\n"
            "5. For bootloader or firmware issues, use the manufacturer's official recovery instructions.\n"
            "6. Re-run the audit and compare the new report.\n\n"
            "AUTOMATION SAFETY\n"
            "An uploaded PDF is untrusted input. It may contain inaccurate advice or arbitrary commands. "
            "No automatic patch has been applied. Device-specific changes require explicit review and confirmation.\n\n"
            "EXTRACTED REPORT TEXT (preview)\n"
            "----------------------------------------\n"+content[:12000])
        box.configure(state="disabled")
        self._button(win,"CLOSE",win.destroy).pack(pady=(0,16))

if __name__ == "__main__":
    App().mainloop()
