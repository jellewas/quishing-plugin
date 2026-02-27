# Privacy Policy for QR Code Scanner

**Last updated: February 27, 2026**

## Overview

QR Code Scanner is a Chrome browser extension that scans and decodes QR codes found on webpages. This privacy policy explains how the extension handles your data.

## Data Collection

**This extension does not collect, store, or transmit any personal data to external servers.**

## How Data Is Handled

### Image Processing
- QR code images are decoded **entirely within your browser**.
- No images or decoded content are sent to any external server or third party.
- Image processing happens locally using the jsQR open-source library.

### Webpage Access
- The extension accesses webpage content **only when you initiate a scan**.
- This access is required to identify and decode QR code images on the page.

### Tab Capture
- When using the "Scan Visible Page" feature, the extension captures a screenshot of the current tab.
- This screenshot is processed **locally in your browser** and is immediately discarded after scanning.

### Local Storage
- The extension temporarily stores the most recent scan result using Chrome's local storage API.
- This data **never leaves your device** and is automatically cleared on the next scan.

## Permissions Explained

| Permission | Why It's Needed |
|---|---|
| `activeTab` | To access the current tab for QR code scanning |
| `scripting` | To inject the QR scanning functionality into webpages |
| `storage` | To temporarily store scan results locally |
| `tabs` | To capture the visible tab for page-wide QR scanning |

## Third-Party Services

This extension does **not** use any third-party analytics, tracking, advertising, or data processing services.

## Open Source Libraries

- **jsQR** (v1.4.0) — QR code decoding library, runs entirely in the browser.

## Changes to This Policy

Any changes to this privacy policy will be reflected in an updated version of the extension.

## Contact

If you have questions about this privacy policy, please open an issue on the extension's support page.
