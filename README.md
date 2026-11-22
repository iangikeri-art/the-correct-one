# Smart Home Camera Security System

A Flask and SQLite security prototype for smart home camera monitoring, featuring Role-Based Access Control (RBAC), camera state anomaly detection, SHA-256 footage integrity verification, and forensic audit logging.

## Key Features
* *RBAC & Authentication:* Separates admin (full control, camera toggles, user provisioning) from member (view-only access).
* *Camera Anomaly Detection:* Tracks camera state changes (ON/OFF) and flags stuck-ON anomalies in the history log.
* *SHA-256 Evidence Integrity:* Computes a SHA-256 hash on uploaded footage to detect tampering and supports playback.
* *Audit Trail & Persistence:* Records user actions and system events in security.db across restarts.

## Running Locally
1. Install Flask and Werkzeug: pip install flask werkzeug
2. Run the app: py app.py
3. Open http://127.0.0.1:5000 in your browser.
