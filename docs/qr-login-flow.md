# QR Login Flow

## Objective
Provide a secure cross-device login experience where a signed-in browser session can issue a QR code, a secondary device can request access by scanning it, and the original session must explicitly approve or deny that request. The device that minted the QR cannot consume the token or complete the login itself.

## Implementation Overview
- **Generate QR** – `src\main\java\org\example\magiclink\controller\QRController.java:36` (`generateQR`) issues the token through `QRService.generateQRToken`, renders the QR image, and tracks the issuing session.
- **Scan QR** – `QRController.scanQR` binds the first scanning session to the token, records device/IP metadata, and prevents the creator session or subsequent scanners from reusing it.
- **Approve / Deny** – `QRController.approveQR` and the POST handlers at the same path ensure only the original session can approve or deny and only after a device has scanned the code.
- **Status Polling & Login** – `QRController.checkStatus` mediates polling from both devices, exposes scan metadata to the creator session, and authenticates the scanning session once approval occurs.
- **Token Lifecycle** – `src\main\java\org\example\magiclink\service\QRService.java` now centralises expiry checks (`hasExpired`/`markExpired`), enforces single-session consumption, and rejects approvals without a recorded scan. `QRTokenEntity` tracks both generating and scanning session IDs.

## Front-End Support
- `src\main\resources\templates\qr-approve.html` shows live device/IP details, disables the action buttons until a scan occurs, and polls `/qr/status` to refresh metadata automatically.
- `src\main\resources\templates\qr-scan.html` remains responsible for polling until the approval arrives and relaying success or denial states to the scanning device.

## Key Safeguards
- Creator session ID must match on approval/denial (`QRController.approveQRPost` / `denyQR`).
- Scanning session ID must match on consumption (`QRService.consumeToken`).
- Tokens auto-expire and transition to `EXPIRED` without leaking metadata.
- Duplicate scans and self-consumption attempts are rejected early in `scanQR`.

## Next Steps
- Consider persisting approval timestamps for audit logging.
- Add integration tests around the QR approval lifecycle to prevent regressions.
