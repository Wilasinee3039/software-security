# Threat Model — <app name>

## 1. Data-flow diagram
(Insert your DFD image. Mark trust boundaries with dashed lines.)

## 2. Elements & trust boundaries
| Element | Type (process/store/entity/flow) | Trust boundary crossed? |
|---|---|---|
| Web client | external entity | yes (Internet -> app) |
| Flask app | process | yes (Internet -> app) |
| SQLite DB (`notes.db`) | data store | yes (app -> data store) |
| `uploads/` store | data store | yes (app -> file system) |

## 3. STRIDE analysis

### Task 2 — STRIDE the elements

| Element | S | T | R | I | D | E |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Web Client** | Spoof client identity | Manipulate request data | Deny sending request | — | Send excessive requests | Attempt unauthorized actions |
| **Flask App** | No authentication on `/notes` | Raw `f.filename` trusted | No request logging | Save-path disclosure | Upload/resource exhaustion | Unauthorized actions |
| **`notes.db`** | — | Unauthorized note modification | No audit trail | Unauthorized note reading | Database/resource exhaustion | — |
| **`uploads/`** | — | Arbitrary file write via filename | No file-operation logging | Resolved path disclosed | Disk exhaustion | Potential unsafe file placement |

## 4. Top 5 risks (likelihood × impact) + mitigation

| Rank | Risk / Threat | Likelihood × Impact | Concrete Mitigation |
|:---:|---|---|---|
| **1** | **Arbitrary File Write / RCE**<br>*(Tampering/EoP on `/upload`)* | **High × High = Critical** | Use `werkzeug.utils.secure_filename()` to strip directory traversal characters and enforce a strict allowlist for safe file extensions. |
| **2** | **Identity Spoofing**<br>*(Spoofing on `/notes`)* | **High × Medium = High** | Implement token-based authentication (e.g., JWT) or session management so the `owner` identity is verified securely by the server, not supplied blindly by the client. |
| **3** | **Storage Exhaustion (DoS)**<br>*(DoS on `/upload`)* | **High × Medium = High** | Configure `app.config['MAX_CONTENT_LENGTH']` in Flask to strictly limit the maximum file size allowed per upload. |
| **4** | **Internal Path Leak**<br>*(Information Disclosure on `/upload`)* | **High × Low = Medium** | Modify the endpoint's response to return only a generic success message or the safe basename of the file, never exposing the absolute server directory path. |
| **5** | **Action Repudiation**<br>*(Repudiation across all endpoints)* | **High × Low = Medium** | Implement application-level logging (using Python's `logging` module) to record the timestamp, source IP, requested endpoint, and action result for every request. |
