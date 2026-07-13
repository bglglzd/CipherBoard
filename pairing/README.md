# CipherBoard offline QR pairing

This module generates and scans only bounded `CBO1:` pairing offers and `CBR1:` pairing responses.
It uses ZXing Core `3.5.4` and CameraX `1.6.1`; it does not use ML Kit, Google Play Services, a
network transport, logs, or persistent storage.

The module deliberately does not declare or request `android.permission.CAMERA`. The app must show
its own explanation and request the runtime permission only after the user explicitly presses
"Scan QR", then bind `PairingQrScannerController` after permission is granted.

Decoded text is limited to 32 KiB of printable ASCII and must have an exact supported prefix. A
single QR symbol has a substantially smaller physical capacity, so generation may reject a valid
but too-large 32 KiB protocol string when ZXing cannot fit it into QR version 40.
