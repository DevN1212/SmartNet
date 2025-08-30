# ⚡ SmartNet

**SmartNet** is an intelligent **CIDR-based network scanner** built in **Java 20** with a sleek **JavaFX UI**.  
It enables fast subnet scanning with threaded execution and provides host information such as:

- ✅ IP reachability
- ✅ Open ports
- ✅ Hostname & MAC address (when available)
- ✅ Real-time results displayed in a JavaFX Table
- ✅ OS Fingerprinting (Optional)

---

## ✨ Features

- 🔍 **CIDR Subnet Scanning** — Scan an entire subnet (e.g., `192.168.1.0/24`) in one go
- ⚡ **Multi-threaded Execution** — Uses thread pools for faster scanning
- 🖥️ **JavaFX UI** — Clean interface with a results table
- 🔄 **Loading Overlay** — Spinner shows scan progress
- 📑 **Export Options** — Scan results can be exported (CSV planned)

---

## 🛠️ Tech Stack

| Language                                                 | UI Framework                                                                                  | Build Tool                                              |
|----------------------------------------------------------|-----------------------------------------------------------------------------------------------|---------------------------------------------------------|
| ![Java](https://skillicons.dev/icons?i=java) <br>Java 20 | ![JavaFX](https://img.shields.io/badge/JavaFX-FF0000?logo=openjdk&logoColor=white) <br>JavaFX | ![Maven](https://skillicons.dev/icons?i=maven)<br>Maven |

---

## 📸 Preview

>Home![SmartNet UI Preview](./docs/home.png)

>Scanning![SmartNet Scanning Interface](./docs/scan.png)


---

## 🚀 Getting Started

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/DevN1212/SmartNet.git
cd SmartNet
```

### 2️⃣ Build & Run with Maven

```bash
./mvnw clean javafx:run
```
---
