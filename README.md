# CyberScan — Advanced Network Security Dashboard

**CyberScan** is a professional-grade, web-based network reconnaissance tool designed for security professionals and enthusiasts. It combines powerful asynchronous port scanning with a premium "Neon Glass" interface, providing real-time visualization and AI-driven insights.

## Key Features

-   **🚀 High-Performance Scanning**: Multi-threaded, asynchronous scanning engine capable of checking thousands of ports in seconds.
-   **🎨 Neon Glass UI**: A stunning, modern dark-mode interface with glassmorphism effects and animated feedback.
-   **📊 AI Risk Threat Score**: Dynamic visual risk assessment based on open port criticality and service types.
-   **🔊 Sonic Recon™**: Real-time voice feedback using Neural Text-to-Speech to "hear" your scan progress.
-   **⚡ Live Metrics**: Real-time donut charts and progress bars that update as the scan progresses.
-   **🔍 Quick Port Check**: Instant tool to verify the status of a specific port without running a full scan.
-   **📄 Reporting**: Export scan results to JSON or print a professional report directly from the dashboard.

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/yourusername/CyberScan.git
    cd CyberScan
    ```

2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  Start the application:
    ```bash
    python3 webapp/app.py
    ```

2.  Open your browser and navigate to:
    ```
    http://127.0.0.1:5000
    ```

3.  **Login Credentials** (Default):
    -   Username: `admin`
    -   Password: `password`
    *(Change these in `webapp/app.py` or via environment variables for production)*

## Technology Stack

-   **Backend**: Python, Flask, Asyncio
-   **Frontend**: HTML5, CSS3 (Modern Variables), JavaScript (ES6+)
-   **Visualization**: Chart.js
-   **Icons**: Ionicons

## Disclaimer

This tool is intended for educational and authorized security testing purposes only. You must have explicit permission to scan target networks. The authors are not responsible for any misuse.

---
*Built by NITECHSPARK*
