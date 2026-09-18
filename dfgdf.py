import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sqlite3
import random
import csv
import math
import hashlib
from datetime import datetime, timedelta

# Optional packages:
#   pip install scikit-learn reportlab
try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    SKLEARN_AVAILABLE = True
except Exception:
    SKLEARN_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False


# ============================================================
# CYBER SHIELD - ENHANCED PROJECT EDITION
# Features:
# - SQLite persistent storage
# - Admin login
# - Real-time simulated monitoring
# - ML severity prediction
# - Anomaly detection
# - Risk score / confidence
# - Critical/High alerts + alert history
# - Incident management
# - Global threat map
# - Search and advanced filtering
# - CSV export
# - PDF security report
# - Trend analytics
# - IP reputation/activity analysis
# ============================================================

APP_TITLE = "CYBER SHIELD - Cyber Security Threat Analysis Center"
DB_FILE = "cyber_shield.db"

# ---------------- COLORS ----------------
BG = "#030811"
SIDEBAR = "#050D18"
PANEL = "#071421"
CARD = "#0A1B2B"
BORDER = "#12344A"
WHITE = "#F1F7FF"
TEXT = "#D7E6F5"
MUTED = "#7189A2"
CYAN = "#00E5FF"
GREEN = "#00E676"
RED = "#FF3155"
ORANGE = "#FFB300"
BLUE = "#2979FF"
PURPLE = "#A970FF"
YELLOW = "#FDD835"

ATTACK_TYPES = [
    "Malware", "Phishing", "DDoS", "Ransomware", "SQL Injection",
    "Brute Force", "XSS Attack", "Man-in-the-Middle", "Zero-Day Exploit",
    "Credential Stuffing", "Botnet", "Spyware", "Trojan",
    "Data Exfiltration", "Port Scanning"
]
SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
STATUSES = ["Blocked", "Investigating", "Resolved", "Monitoring", "Escalated", "False Positive"]
COUNTRIES = [
    "India", "USA", "UK", "Germany", "Russia", "China", "Japan", "Canada",
    "France", "Brazil", "Australia", "Singapore", "South Korea",
    "Netherlands", "Sweden", "Italy", "Spain", "UAE", "Mexico", "South Africa"
]
USERS = [
    "admin", "root", "security_admin", "john", "alex", "employee01",
    "employee02", "employee03", "guest", "manager", "developer",
    "database_admin", "network_admin", "hr_user", "finance_user"
]
PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "ICMP", "DNS", "SSH", "FTP"]
DEVICES = [
    "Windows PC", "Linux Server", "Web Server", "Database Server", "Router",
    "Firewall", "Cloud Server", "Laptop", "Mobile Device", "IoT Device",
    "Mail Server", "DNS Server"
]
OPERATING_SYSTEMS = [
    "Windows 11", "Windows 10", "Ubuntu Linux", "Kali Linux", "Debian",
    "CentOS", "Red Hat", "macOS", "Android", "iOS"
]
DETECTION_METHODS = [
    "Firewall", "IDS", "IPS", "Antivirus", "SIEM", "EDR",
    "Log Analysis", "Behavior Analysis", "Threat Intelligence", "Network Monitoring"
]
ACTIONS = [
    "IP Blocked", "Connection Dropped", "Account Locked", "File Quarantined",
    "Traffic Filtered", "Alert Generated", "Session Terminated",
    "Device Isolated", "Investigation Started", "No Action"
]
DEPARTMENTS = [
    "IT", "Finance", "HR", "Marketing", "Development",
    "Operations", "Security", "Management", "Sales", "Research"
]
LOCATIONS = [
    "Hyderabad", "Bangalore", "Mumbai", "Delhi", "Chennai", "Pune",
    "Visakhapatnam", "Vijayawada", "New York", "London", "Berlin", "Singapore"
]
PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080]

COUNTRY_COORDS = {
    "USA": (-100, 40), "Canada": (-106, 56), "Mexico": (-102, 23),
    "Brazil": (-52, -10), "UK": (-3, 55), "France": (2, 46),
    "Germany": (10, 51), "Netherlands": (5, 52), "Sweden": (15, 62),
    "Italy": (12, 42), "Spain": (-4, 40), "Russia": (90, 60),
    "India": (78, 22), "China": (104, 35), "Japan": (138, 36),
    "South Korea": (127, 36), "Singapore": (104, 1), "Australia": (134, -25),
    "UAE": (54, 24), "South Africa": (24, -30)
}

SEVERITY_SCORE = {
    "Critical": 95,
    "High": 80,
    "Medium": 55,
    "Low": 27,
    "Informational": 8
}


# ============================================================
# DATABASE
# ============================================================

def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def db_connect():
    return sqlite3.connect(DB_FILE)


def init_database():
    with db_connect() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT,
                attack TEXT,
                severity TEXT,
                predicted_severity TEXT,
                status TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                country TEXT,
                user TEXT,
                protocol TEXT,
                device TEXT,
                os TEXT,
                detection TEXT,
                action TEXT,
                department TEXT,
                location TEXT,
                risk INTEGER,
                confidence INTEGER,
                anomaly INTEGER,
                incident_id INTEGER
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_id INTEGER,
                created_at TEXT,
                level TEXT,
                message TEXT,
                acknowledged INTEGER DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_id INTEGER,
                title TEXT,
                description TEXT,
                status TEXT,
                assigned_to TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        cur.execute(
            "INSERT OR IGNORE INTO users VALUES (?, ?, ?)",
            ("admin", hash_password("admin123"), "Administrator")
        )
        conn.commit()


def db_count(table):
    with db_connect() as conn:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


# ============================================================
# THREAT GENERATION + ML
# ============================================================

def random_ip(private=False):
    if private:
        return f"192.168.{random.randint(0, 10)}.{random.randint(1, 254)}"
    return (
        f"{random.randint(11, 223)}.{random.randint(0,255)}."
        f"{random.randint(0,255)}.{random.randint(1,254)}"
    )


def generate_raw_threat():
    attack = random.choice(ATTACK_TYPES)
    severity = random.choices(SEVERITIES, weights=[7, 18, 35, 30, 10])[0]
    status = random.choice(STATUSES)
    source_ip = random_ip()
    destination_ip = random_ip(private=True)
    source_port = random.randint(1024, 65535)
    destination_port = random.choice(PORTS)
    country = random.choice(COUNTRIES)
    user = random.choice(USERS)
    protocol = random.choice(PROTOCOLS)
    device = random.choice(DEVICES)
    os_name = random.choice(OPERATING_SYSTEMS)
    detection = random.choice(DETECTION_METHODS)
    action = random.choice(ACTIONS)
    department = random.choice(DEPARTMENTS)
    location = random.choice(LOCATIONS)

    base = SEVERITY_SCORE[severity]
    risk = max(1, min(100, base + random.randint(-9, 9)))
    confidence = random.randint(65, 99)

    return {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "attack": attack,
        "severity": severity,
        "status": status,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "country": country,
        "user": user,
        "protocol": protocol,
        "device": device,
        "os": os_name,
        "detection": detection,
        "action": action,
        "department": department,
        "location": location,
        "risk": risk,
        "confidence": confidence
    }


attack_code = {x: i for i, x in enumerate(ATTACK_TYPES)}
protocol_code = {x: i for i, x in enumerate(PROTOCOLS)}
device_code = {x: i for i, x in enumerate(DEVICES)}
country_code = {x: i for i, x in enumerate(COUNTRIES)}
severity_code = {x: i for i, x in enumerate(SEVERITIES)}


def ml_features(item):
    return [[
        attack_code[item["attack"]],
        protocol_code[item["protocol"]],
        device_code[item["device"]],
        country_code[item["country"]],
        item["destination_port"],
        item["risk"],
        item["confidence"],
        1 if item["user"] in ("admin", "root", "security_admin", "database_admin") else 0
    ]]


ml_model = None
anomaly_model = None


def train_models():
    global ml_model, anomaly_model

    if not SKLEARN_AVAILABLE:
        ml_model = None
        anomaly_model = None
        return

    samples = [generate_raw_threat() for _ in range(1200)]
    X = []
    y = []
    XA = []

    for item in samples:
        X.extend(ml_features(item))
        y.append(item["severity"])
        XA.append(X[-1])

    ml_model = RandomForestClassifier(
        n_estimators=120,
        random_state=42,
        max_depth=10
    )
    ml_model.fit(X, y)

    anomaly_model = IsolationForest(
        contamination=0.08,
        random_state=42
    )
    anomaly_model.fit(XA)


def predict_threat(item):
    """Return ML prediction and anomaly flag.
    A transparent rule-based fallback is used if scikit-learn is unavailable.
    """
    if ml_model is not None:
        prediction = ml_model.predict(ml_features(item))[0]
    else:
        # Fallback for machines without scikit-learn.
        risk = item["risk"]
        if risk >= 90:
            prediction = "Critical"
        elif risk >= 70:
            prediction = "High"
        elif risk >= 40:
            prediction = "Medium"
        elif risk >= 15:
            prediction = "Low"
        else:
            prediction = "Informational"

    if anomaly_model is not None:
        anomaly = int(anomaly_model.predict(ml_features(item))[0] == -1)
    else:
        anomaly = int(
            item["risk"] >= 92
            or item["source_port"] < 1024 and item["attack"] == "Port Scanning"
        )

    return prediction, anomaly


def enrich_threat(item):
    predicted, anomaly = predict_threat(item)
    item["predicted_severity"] = predicted
    item["anomaly"] = anomaly
    return item


# ============================================================
# DATA STORAGE
# ============================================================

THREAT_COLUMNS = [
    "id", "time", "attack", "severity", "predicted_severity", "status",
    "source_ip", "destination_ip", "source_port", "destination_port",
    "country", "user", "protocol", "device", "os", "detection", "action",
    "department", "location", "risk", "confidence", "anomaly", "incident_id"
]


def insert_threat(item, create_alert=True):
    item = enrich_threat(item)
    with db_connect() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO threats (
                event_time, attack, severity, predicted_severity, status,
                source_ip, destination_ip, source_port, destination_port,
                country, user, protocol, device, os, detection, action,
                department, location, risk, confidence, anomaly, incident_id
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            item["time"], item["attack"], item["severity"],
            item["predicted_severity"], item["status"], item["source_ip"],
            item["destination_ip"], item["source_port"], item["destination_port"],
            item["country"], item["user"], item["protocol"], item["device"],
            item["os"], item["detection"], item["action"], item["department"],
            item["location"], item["risk"], item["confidence"], item["anomaly"], None
        ))
        threat_id = cur.lastrowid

        level = None
        if item["severity"] == "Critical" or item["risk"] >= 90:
            level = "CRITICAL"
        elif item["severity"] == "High" or item["risk"] >= 70:
            level = "HIGH"
        elif item["anomaly"]:
            level = "ANOMALY"

        if create_alert and level:
            cur.execute("""
                INSERT INTO alerts(threat_id, created_at, level, message)
                VALUES(?,?,?,?)
            """, (
                threat_id,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                level,
                f"{level}: {item['attack']} from {item['source_ip']} "
                f"(risk {item['risk']})"
            ))
        conn.commit()
    return threat_id


def seed_database():
    if db_count("threats") > 0:
        return
    for _ in range(500):
        item = generate_raw_threat()
        # Historical timestamps for analytics.
        item["time"] = (
            datetime.now() - timedelta(minutes=random.randint(0, 60 * 24 * 30))
        ).strftime("%Y-%m-%d %H:%M:%S")
        insert_threat(item, create_alert=False)


def row_to_dict(row):
    keys = THREAT_COLUMNS
    return dict(zip(keys, row))


def get_all_threats(limit=3000):
    with db_connect() as conn:
        rows = conn.execute("""
            SELECT id, event_time, attack, severity, predicted_severity, status,
                   source_ip, destination_ip, source_port, destination_port,
                   country, user, protocol, device, os, detection, action,
                   department, location, risk, confidence, anomaly, incident_id
            FROM threats ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
    return [row_to_dict(r) for r in rows]


def update_threat_status(threat_id, status):
    with db_connect() as conn:
        conn.execute("UPDATE threats SET status=? WHERE id=?", (status, threat_id))
        conn.commit()


# ============================================================
# MAIN APPLICATION
# ============================================================

class CyberShieldApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1550x920")
        self.root.minsize(1200, 720)
        self.root.configure(bg=BG)

        self.logged_user = "admin"
        self.current_page = "Dashboard"
        self.live_mode = False
        self.live_job = None
        self.alert_job = None
        self.web_job = None
        self.web_step = 0
        self.search_var = tk.StringVar()
        self.severity_var = tk.StringVar(value="All")
        self.status_var = tk.StringVar(value="All")
        self.attack_var = tk.StringVar(value="All")
        self.country_var = tk.StringVar(value="All")
        self.protocol_var = tk.StringVar(value="All")
        self.department_var = tk.StringVar(value="All")

        self.build_style()
        self.build_layout()
        self.update_clock()
        self.refresh_alert_badge()
        self.show_dashboard()
        self.root.after(1000, self.alert_watcher)

    # ---------------- UI ----------------

    def build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(
            "Treeview",
            background=PANEL,
            foreground=TEXT,
            fieldbackground=PANEL,
            rowheight=30,
            borderwidth=0,
            font=("Segoe UI", 9)
        )
        style.configure(
            "Treeview.Heading",
            background="#0B2638",
            foreground=CYAN,
            font=("Segoe UI", 9, "bold")
        )
        style.map(
            "Treeview",
            background=[("selected", "#123B55")],
            foreground=[("selected", WHITE)]
        )
        style.configure(
            "TCombobox",
            fieldbackground=CARD,
            background=CARD,
            foreground=WHITE
        )

    def build_layout(self):
        self.background = tk.Canvas(self.root, bg=BG, highlightthickness=0)
        self.background.place(x=240, y=0, relwidth=1, relheight=1, width=-240)
        self.root.tk.call("lower", self.background._w)

        self.sidebar = tk.Frame(self.root, bg=SIDEBAR, width=240)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        tk.Label(
            self.sidebar, text="🛡", font=("Segoe UI", 34),
            fg=CYAN, bg=SIDEBAR
        ).pack(pady=(18, 0))
        tk.Label(
            self.sidebar, text="CYBER SHIELD",
            font=("Segoe UI", 17, "bold"), fg=WHITE, bg=SIDEBAR
        ).pack()
        tk.Label(
            self.sidebar, text="CYBER ALLIANCE",
            font=("Segoe UI", 8, "bold"), fg=CYAN, bg=SIDEBAR
        ).pack(pady=(2, 10))

        self.draw_sidebar_web()

        self.menu = tk.Frame(self.sidebar, bg=SIDEBAR)
        self.menu.pack(fill="x", pady=3)

        self.menu_button("▣   Dashboard", self.show_dashboard)
        self.menu_button("⚠   Threat Monitor", self.show_threats)
        self.menu_button("◉   Security Analytics", self.show_analytics)
        self.menu_button("🧠   ML & Anomaly", self.show_ml)
        self.menu_button("🚨   Alert Center", self.show_alerts)
        self.menu_button("📋   Incidents", self.show_incidents)
        self.menu_button("🌐   Global Threat Map", self.show_map)
        self.menu_button("⚙   System", self.show_system)

        tk.Frame(self.sidebar, bg=BORDER, height=1).pack(fill="x", padx=20, pady=12)

        self.status_label = tk.Label(
            self.sidebar, text="●  SOC ONLINE",
            font=("Segoe UI", 10, "bold"), fg=GREEN, bg=SIDEBAR
        )
        self.status_label.pack(anchor="w", padx=25)

        self.alert_badge = tk.Label(
            self.sidebar, text="Alerts: 0",
            font=("Segoe UI", 8, "bold"), fg=RED, bg=SIDEBAR
        )
        self.alert_badge.pack(anchor="w", padx=25, pady=3)

        self.live_button = tk.Button(
            self.sidebar, text="○ LIVE: OFF",
            command=self.toggle_live, bg="#0B1D2B", fg=MUTED,
            activebackground="#12304A", activeforeground=GREEN,
            relief="flat", font=("Segoe UI", 9, "bold"),
            padx=10, pady=8
        )
        self.live_button.pack(fill="x", padx=20, pady=7)

        self.content = tk.Frame(self.root, bg=BG)
        self.content.pack(side="right", fill="both", expand=True)

        self.header = tk.Frame(self.content, bg=BG, height=70)
        self.header.pack(fill="x")
        self.header.pack_propagate(False)

        self.header_title = tk.Label(
            self.header, text="Security Operations Dashboard",
            font=("Segoe UI", 21, "bold"), fg=WHITE, bg=BG
        )
        self.header_title.pack(side="left", padx=25)

        self.user_label = tk.Label(
            self.header, text="ADMINISTRATOR",
            font=("Segoe UI", 9, "bold"), fg=CYAN, bg=BG
        )
        self.user_label.pack(side="right", padx=10)

        self.clock_label = tk.Label(
            self.header, text="", font=("Consolas", 10),
            fg=MUTED, bg=BG
        )
        self.clock_label.pack(side="right", padx=20)

        self.root.bind("<Configure>", lambda e: self.draw_background())

    def draw_sidebar_web(self):
        canvas = tk.Canvas(
            self.sidebar, height=100, bg=SIDEBAR, highlightthickness=0
        )
        canvas.pack(fill="x", padx=10)

        w, h = 215, 100
        cx, cy = w / 2, h / 2 - 4
        for r in (18, 32, 46):
            pts = []
            for i in range(16):
                a = 2 * math.pi * i / 16
                pts += [cx + math.cos(a) * r, cy + math.sin(a) * r]
            canvas.create_polygon(pts, outline="#0B3347", fill="")
        for i in range(16):
            a = 2 * math.pi * i / 16
            canvas.create_line(cx, cy, cx + math.cos(a) * 46,
                               cy + math.sin(a) * 46, fill="#0B3347")
        canvas.create_oval(cx-5, cy-5, cx+5, cy+5, fill=CYAN, outline="")
        canvas.create_text(
            cx, h-10, text="CYBER WEB NETWORK",
            fill=MUTED, font=("Segoe UI", 7, "bold")
        )

    def draw_background(self):
        try:
            self.background.delete("all")
            w = max(self.background.winfo_width(), 1200)
            h = max(self.background.winfo_height(), 700)
            for x in range(0, w, 45):
                self.background.create_line(x, 0, x, h, fill="#0B2638")
            for y in range(0, h, 45):
                self.background.create_line(0, y, w, y, fill="#0B2638")
            cx, cy = w * .78, h * .50
            for r in (80, 150, 220, 290):
                pts = []
                for i in range(20):
                    a = 2 * math.pi * i / 20
                    pts += [cx + math.cos(a)*r, cy + math.sin(a)*r]
                self.background.create_polygon(pts, outline="#0A3041", fill="")
        except Exception:
            pass

    def update_clock(self):
        self.clock_label.config(text=datetime.now().strftime("%d-%m-%Y   %H:%M:%S"))
        self.root.after(1000, self.update_clock)

    def menu_button(self, text, command):
        btn = tk.Button(
            self.menu, text=text, command=command, anchor="w",
            font=("Segoe UI", 10), fg=TEXT, bg=SIDEBAR,
            activebackground="#12304A", activeforeground=CYAN,
            relief="flat", bd=0, padx=25, pady=10, cursor="hand2"
        )
        btn.pack(fill="x")
        btn.bind("<Enter>", lambda e: btn.configure(bg="#0B1E2E", fg=CYAN))
        btn.bind("<Leave>", lambda e: btn.configure(bg=SIDEBAR, fg=TEXT))

    def clear_content(self):
        for widget in self.content.winfo_children():
            if widget != self.header:
                widget.destroy()

    def page_title(self, title):
        self.header_title.config(text=title)

    def card(self, parent, title, value, color):
        f = tk.Frame(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        f.pack(side="left", fill="both", expand=True, padx=5)
        tk.Label(
            f, text=title, fg=MUTED, bg=CARD,
            font=("Segoe UI", 8, "bold")
        ).pack(anchor="w", padx=16, pady=(11, 2))
        lbl = tk.Label(
            f, text=str(value), fg=color, bg=CARD,
            font=("Segoe UI", 18, "bold")
        )
        lbl.pack(anchor="w", padx=16, pady=(0, 10))
        return lbl

    def panel(self, parent):
        return tk.Frame(
            parent, bg=PANEL,
            highlightbackground=BORDER, highlightthickness=1
        )

    # ---------------- Filtering ----------------

    def filtered_data(self):
        data = get_all_threats()
        search = self.search_var.get().lower().strip()

        result = []
        for x in data:
            blob = " ".join(str(x.get(k, "")) for k in (
                "id", "attack", "severity", "predicted_severity", "status",
                "source_ip", "destination_ip", "country", "user", "device",
                "protocol", "department"
            )).lower()

            if search and search not in blob:
                continue
            if self.severity_var.get() != "All" and x["severity"] != self.severity_var.get():
                continue
            if self.status_var.get() != "All" and x["status"] != self.status_var.get():
                continue
            if self.attack_var.get() != "All" and x["attack"] != self.attack_var.get():
                continue
            if self.country_var.get() != "All" and x["country"] != self.country_var.get():
                continue
            if self.protocol_var.get() != "All" and x["protocol"] != self.protocol_var.get():
                continue
            if self.department_var.get() != "All" and x["department"] != self.department_var.get():
                continue
            result.append(x)
        return result

    def filter_bar(self, parent):
        f = tk.Frame(parent, bg=BG)
        f.pack(fill="x", padx=25, pady=8)

        tk.Label(f, text="Search:", fg=MUTED, bg=BG).pack(side="left")
        e = tk.Entry(
            f, textvariable=self.search_var, width=17, bg=CARD, fg=WHITE,
            insertbackground=WHITE, relief="flat"
        )
        e.pack(side="left", padx=5, ipady=5)

        def combo(var, values, width):
            c = ttk.Combobox(
                f, textvariable=var, values=["All"] + values,
                state="readonly", width=width
            )
            c.pack(side="left", padx=3)
            c.bind("<<ComboboxSelected>>", lambda _: self.refresh_current())
            return c

        combo(self.severity_var, SEVERITIES, 12)
        combo(self.status_var, STATUSES, 14)
        combo(self.attack_var, ATTACK_TYPES, 17)
        combo(self.country_var, COUNTRIES, 13)
        combo(self.protocol_var, PROTOCOLS, 10)
        combo(self.department_var, DEPARTMENTS, 12)

        tk.Button(
            f, text="RESET", command=self.reset_filters,
            bg="#20364A", fg=WHITE, relief="flat", padx=9, pady=5
        ).pack(side="left", padx=4)
        e.bind("<Return>", lambda _: self.refresh_current())

    def reset_filters(self):
        self.search_var.set("")
        self.severity_var.set("All")
        self.status_var.set("All")
        self.attack_var.set("All")
        self.country_var.set("All")
        self.protocol_var.set("All")
        self.department_var.set("All")
        self.refresh_current()

    def refresh_current(self):
        {
            "Dashboard": self.show_dashboard,
            "Threat Monitor": self.show_threats,
            "Security Analytics": self.show_analytics
        }.get(self.current_page, self.show_dashboard)()

    # ========================================================
    # DASHBOARD
    # ========================================================

    def show_dashboard(self):
        self.current_page = "Dashboard"
        self.clear_content()
        self.page_title("Security Operations Dashboard")

        self.filter_bar(self.content)
        data = self.filtered_data()

        total = len(data)
        critical = sum(x["severity"] == "Critical" for x in data)
        high = sum(x["severity"] == "High" for x in data)
        anomalies = sum(x["anomaly"] for x in data)
        avg_risk = sum(x["risk"] for x in data) / total if total else 0

        cards = tk.Frame(self.content, bg=BG)
        cards.pack(fill="x", padx=25, pady=7)
        self.card(cards, "TOTAL EVENTS", total, CYAN)
        self.card(cards, "CRITICAL", critical, RED)
        self.card(cards, "HIGH", high, ORANGE)
        self.card(cards, "ANOMALIES", anomalies, PURPLE)
        self.card(cards, "AVG RISK", f"{avg_risk:.1f}", YELLOW)

        body = tk.Frame(self.content, bg=BG)
        body.pack(fill="both", expand=True, padx=25, pady=8)

        left = self.panel(body)
        left.pack(side="left", fill="both", expand=True, padx=5)

        right = self.panel(body)
        right.pack(side="left", fill="both", expand=True, padx=5)

        tk.Label(
            left, text="⚡ ATTACK DISTRIBUTION",
            font=("Segoe UI", 11, "bold"), fg=CYAN, bg=PANEL
        ).pack(anchor="w", padx=15, pady=12)

        counts = {}
        for x in data:
            counts[x["attack"]] = counts.get(x["attack"], 0) + 1
        for attack, count in sorted(counts.items(), key=lambda z: z[1], reverse=True)[:10]:
            row = tk.Frame(left, bg=PANEL)
            row.pack(fill="x", padx=15, pady=3)
            tk.Label(row, text=attack, width=19, anchor="w", fg=TEXT, bg=PANEL).pack(side="left")
            barbg = tk.Frame(row, bg="#102D40", height=10)
            barbg.pack(side="left", fill="x", expand=True, padx=5)
            maxv = max(counts.values(), default=1)
            tk.Frame(barbg, bg=CYAN, height=10, width=int(170 * count / maxv)).pack(side="left")
            tk.Label(row, text=str(count), width=4, fg=WHITE, bg=PANEL).pack(side="right")

        tk.Label(
            right, text="🚨 SECURITY HEALTH",
            font=("Segoe UI", 11, "bold"), fg=CYAN, bg=PANEL
        ).pack(anchor="w", padx=15, pady=12)

        self.health_meter(right, "Critical Risk", critical, max(total, 1), RED)
        self.health_meter(right, "High Risk", high, max(total, 1), ORANGE)
        self.health_meter(right, "Anomalies", anomalies, max(total, 1), PURPLE)

        tk.Label(
            right,
            text=(
                "\nRecommended Actions\n"
                "• Investigate critical events first\n"
                "• Review repeated source IP activity\n"
                "• Examine anomalous behavior\n"
                "• Monitor privileged accounts\n"
                "• Export reports for periodic review"
            ),
            justify="left", fg=TEXT, bg=PANEL,
            font=("Consolas", 10)
        ).pack(anchor="w", padx=20, pady=15)

    def health_meter(self, parent, title, value, total, color):
        tk.Label(parent, text=f"{title}: {value}", fg=TEXT, bg=PANEL).pack(anchor="w", padx=20, pady=(7, 1))
        bg = tk.Frame(parent, bg="#102D40", height=15)
        bg.pack(fill="x", padx=20)
        tk.Frame(bg, bg=color, height=15, width=300 * value / total).pack(side="left")

    # ========================================================
    # THREAT MONITOR
    # ========================================================

    def show_threats(self):
        self.current_page = "Threat Monitor"
        self.clear_content()
        self.page_title("Threat Intelligence Monitor")
        self.filter_bar(self.content)

        top = tk.Frame(self.content, bg=BG)
        top.pack(fill="x", padx=25, pady=3)

        tk.Label(
            top, text=f"{len(self.filtered_data())} security events",
            fg=MUTED, bg=BG
        ).pack(side="left")

        tk.Button(
            top, text="+ Add Threat", command=self.add_threat,
            bg="#075E54", fg=WHITE, relief="flat", padx=10, pady=6
        ).pack(side="right")

        tk.Button(
            top, text="Export CSV", command=self.export_csv,
            bg="#145DA0", fg=WHITE, relief="flat", padx=10, pady=6
        ).pack(side="right", padx=4)

        tk.Button(
            top, text="PDF Report", command=self.export_pdf,
            bg="#6A3FA0", fg=WHITE, relief="flat", padx=10, pady=6
        ).pack(side="right", padx=4)

        frame = tk.Frame(self.content, bg=BG)
        frame.pack(fill="both", expand=True, padx=25, pady=5)

        cols = (
            "ID", "Time", "Attack", "Actual", "ML Prediction", "Source IP",
            "Country", "Protocol", "Status", "Risk", "Anomaly"
        )
        table = ttk.Treeview(frame, columns=cols, show="headings")
        widths = {
            "ID": 50, "Time": 145, "Attack": 145, "Actual": 85,
            "ML Prediction": 105, "Source IP": 125, "Country": 95,
            "Protocol": 80, "Status": 110, "Risk": 65, "Anomaly": 70
        }
        for c in cols:
            table.heading(c, text=c)
            table.column(c, width=widths[c], anchor="center")

        sy = ttk.Scrollbar(frame, orient="vertical", command=table.yview)
        sx = ttk.Scrollbar(frame, orient="horizontal", command=table.xview)
        table.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        sy.pack(side="right", fill="y")
        sx.pack(side="bottom", fill="x")
        table.pack(fill="both", expand=True)

        data = self.filtered_data()
        for item in data:
            table.insert(
                "", "end",
                values=(
                    item["id"], item["time"], item["attack"], item["severity"],
                    item["predicted_severity"], item["source_ip"], item["country"],
                    item["protocol"], item["status"], item["risk"],
                    "YES" if item["anomaly"] else "NO"
                ),
                tags=(item["severity"], "anomaly" if item["anomaly"] else "normal")
            )

        table.tag_configure("Critical", foreground=RED)
        table.tag_configure("High", foreground=ORANGE)
        table.tag_configure("Medium", foreground=YELLOW)
        table.tag_configure("Low", foreground=GREEN)
        table.tag_configure("Informational", foreground=BLUE)
        table.tag_configure("anomaly", background="#24172D")

        def details(_=None):
            sel = table.selection()
            if not sel:
                return
            tid = int(table.item(sel[0])["values"][0])
            item = next((x for x in data if x["id"] == tid), None)
            if item:
                self.show_details(item)

        table.bind("<Double-1>", details)

    def add_threat(self):
        item = generate_raw_threat()
        tid = insert_threat(item)
        self.show_threats()
        if item["severity"] in ("Critical", "High") or item["risk"] >= 90:
            messagebox.showwarning(
                "Security Alert",
                f"Threat #{tid} detected!\n\n"
                f"Attack: {item['attack']}\nRisk: {item['risk']}\n"
                f"Source: {item['source_ip']}"
            )

    # ========================================================
    # DETAILS + IP INTELLIGENCE
    # ========================================================

    def show_details(self, item):
        win = tk.Toplevel(self.root)
        win.title(f"Threat #{item['id']} Investigation")
        win.geometry("760x760")
        win.configure(bg=BG)

        tk.Label(
            win, text="⚠ THREAT INVESTIGATION",
            font=("Segoe UI", 20, "bold"), fg=CYAN, bg=BG
        ).pack(pady=16)

        panel = self.panel(win)
        panel.pack(fill="both", expand=True, padx=25, pady=8)

        fields = [
            ("Threat ID", item["id"]), ("Detection Time", item["time"]),
            ("Attack Type", item["attack"]), ("Actual Severity", item["severity"]),
            ("ML Prediction", item["predicted_severity"]), ("Status", item["status"]),
            ("Source IP", item["source_ip"]), ("Destination IP", item["destination_ip"]),
            ("Source Port", item["source_port"]), ("Destination Port", item["destination_port"]),
            ("Country", item["country"]), ("User", item["user"]),
            ("Protocol", item["protocol"]), ("Device", item["device"]),
            ("Operating System", item["os"]), ("Detection Method", item["detection"]),
            ("Action Taken", item["action"]), ("Department", item["department"]),
            ("Location", item["location"]), ("Risk Score", f"{item['risk']}/100"),
            ("Confidence", f"{item['confidence']}%"),
            ("Anomaly", "YES - unusual behavior" if item["anomaly"] else "NO")
        ]

        for name, value in fields:
            row = tk.Frame(panel, bg=PANEL)
            row.pack(fill="x", padx=18, pady=2)
            tk.Label(
                row, text=name, width=20, anchor="w",
                fg=MUTED, bg=PANEL, font=("Segoe UI", 9, "bold")
            ).pack(side="left")
            color = RED if name == "Actual Severity" and value == "Critical" else WHITE
            tk.Label(row, text=str(value), fg=color, bg=PANEL).pack(side="left")

        ip_score = self.ip_reputation_score(item["source_ip"])
        tk.Label(
            panel,
            text=f"\nIP Activity / Reputation Score: {ip_score}/100",
            fg=ORANGE if ip_score >= 70 else GREEN,
            bg=PANEL, font=("Segoe UI", 11, "bold")
        ).pack(anchor="w", padx=20, pady=8)

        tk.Button(
            panel, text="Create Incident",
            command=lambda: self.create_incident_for(item, win),
            bg="#6A3FA0", fg=WHITE, relief="flat", padx=12, pady=7
        ).pack(anchor="w", padx=20, pady=10)

    def ip_reputation_score(self, source_ip):
        with db_connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM threats WHERE source_ip=?",
                (source_ip,)
            ).fetchone()[0]
            avg_risk = conn.execute(
                "SELECT COALESCE(AVG(risk),0) FROM threats WHERE source_ip=?",
                (source_ip,)
            ).fetchone()[0]
        return min(100, int(count * 10 + avg_risk * 0.7))

    # ========================================================
    # ANALYTICS
    # ========================================================

    def show_analytics(self):
        self.current_page = "Security Analytics"
        self.clear_content()
        self.page_title("Security Analytics")
        self.filter_bar(self.content)

        data = self.filtered_data()
        if not data:
            tk.Label(
                self.content, text="No data for selected filters.",
                fg=MUTED, bg=BG, font=("Segoe UI", 14)
            ).pack(pady=40)
            return

        total = len(data)
        avg_risk = sum(x["risk"] for x in data) / total
        avg_conf = sum(x["confidence"] for x in data) / total
        attacks = {}
        countries = {}
        protocols = {}
        for x in data:
            attacks[x["attack"]] = attacks.get(x["attack"], 0) + 1
            countries[x["country"]] = countries.get(x["country"], 0) + 1
            protocols[x["protocol"]] = protocols.get(x["protocol"], 0) + 1

        cards = tk.Frame(self.content, bg=BG)
        cards.pack(fill="x", padx=25, pady=7)
        self.card(cards, "TOTAL", total, CYAN)
        self.card(cards, "TOP ATTACK", max(attacks, key=attacks.get), RED)
        self.card(cards, "TOP COUNTRY", max(countries, key=countries.get), ORANGE)
        self.card(cards, "AVG RISK", f"{avg_risk:.1f}", PURPLE)
        self.card(cards, "CONFIDENCE", f"{avg_conf:.1f}%", GREEN)

        body = tk.Frame(self.content, bg=BG)
        body.pack(fill="both", expand=True, padx=25, pady=10)

        p1 = self.panel(body)
        p1.pack(side="left", fill="both", expand=True, padx=5)
        p2 = self.panel(body)
        p2.pack(side="left", fill="both", expand=True, padx=5)

        tk.Label(p1, text="📈 24-HOUR THREAT TREND",
                 font=("Segoe UI", 11, "bold"), fg=CYAN, bg=PANEL).pack(
            anchor="w", padx=15, pady=10
        )
        self.draw_trend(p1, data)

        tk.Label(p2, text="🌐 TOP SOURCE COUNTRIES",
                 font=("Segoe UI", 11, "bold"), fg=CYAN, bg=PANEL).pack(
            anchor="w", padx=15, pady=10
        )
        for country, count in sorted(countries.items(), key=lambda z: z[1], reverse=True)[:10]:
            row = tk.Frame(p2, bg=PANEL)
            row.pack(fill="x", padx=15, pady=3)
            tk.Label(row, text=country, width=16, anchor="w", fg=TEXT, bg=PANEL).pack(side="left")
            tk.Label(row, text=str(count), fg=WHITE, bg=PANEL).pack(side="right")
            bg = tk.Frame(row, bg="#102D40", height=9)
            bg.pack(side="left", fill="x", expand=True, padx=5)
            mx = max(countries.values())
            tk.Frame(bg, bg=ORANGE, height=9, width=170*count/mx).pack(side="left")

        self.add_report_button()

    def draw_trend(self, parent, data):
        canvas = tk.Canvas(parent, bg=PANEL, highlightthickness=0, height=260)
        canvas.pack(fill="x", padx=12, pady=5)

        buckets = [0] * 24
        now = datetime.now()
        for x in data:
            try:
                dt = datetime.strptime(x["time"], "%Y-%m-%d %H:%M:%S")
                age = int((now - dt).total_seconds() // 3600)
                if 0 <= age < 24:
                    buckets[23-age] += 1
            except Exception:
                pass

        w, h = 600, 230
        mx = max(buckets, default=1)
        points = []
        for i, v in enumerate(buckets):
            px = 25 + i * (w - 50) / 23
            py = h - 25 - (v / mx) * (h - 55)
            points += [px, py]

        if len(points) >= 4:
            canvas.create_line(points, fill=CYAN, width=3, smooth=True)
        for i, v in enumerate(buckets):
            px = 25 + i * (w - 50) / 23
            py = h - 25 - (v / mx) * (h - 55)
            canvas.create_oval(px-3, py-3, px+3, py+3, fill=CYAN, outline="")
            if i % 4 == 0:
                canvas.create_text(px, h-8, text=f"{i}h", fill=MUTED, font=("Segoe UI", 7))
        canvas.config(scrollregion=(0, 0, w, h))

    def add_report_button(self):
        b = tk.Frame(self.content, bg=BG)
        b.pack(fill="x", padx=25, pady=5)
        tk.Button(
            b, text="Generate Professional PDF Report",
            command=self.export_pdf, bg="#6A3FA0", fg=WHITE,
            relief="flat", padx=14, pady=7
        ).pack(side="right")

    # ========================================================
    # ML & ANOMALY
    # ========================================================

    def show_ml(self):
        self.current_page = "ML & Anomaly"
        self.clear_content()
        self.page_title("Machine Learning & Anomaly Detection")

        data = get_all_threats()
        predicted_correct = sum(
            x["severity"] == x["predicted_severity"] for x in data
        )
        accuracy = predicted_correct / len(data) * 100 if data else 0
        anomalies = sum(x["anomaly"] for x in data)

        cards = tk.Frame(self.content, bg=BG)
        cards.pack(fill="x", padx=25, pady=15)
        self.card(cards, "MODEL", "Random Forest" if SKLEARN_AVAILABLE else "Fallback", CYAN)
        self.card(cards, "MODEL CHECK", f"{accuracy:.1f}%", GREEN)
        self.card(cards, "ANOMALIES", anomalies, PURPLE)
        self.card(cards, "FEATURES", "8", ORANGE)

        panel = self.panel(self.content)
        panel.pack(fill="both", expand=True, padx=25, pady=10)

        text = (
            "MACHINE LEARNING PIPELINE\n\n"
            "1. Threat event generation / collection\n"
            "2. Feature encoding\n"
            "3. Random Forest severity prediction\n"
            "4. Isolation Forest anomaly detection\n"
            "5. Risk and confidence scoring\n"
            "6. Alert generation for high-risk activity\n\n"
            "FEATURES USED\n"
            "• Attack type\n• Protocol\n• Device\n• Country\n"
            "• Destination port\n• Risk score\n• Confidence\n"
            "• Privileged-account indicator\n\n"
            f"scikit-learn available: {'YES' if SKLEARN_AVAILABLE else 'NO'}\n"
            "The model is trained on the project's simulated security events."
        )
        tk.Label(
            panel, text=text, justify="left", anchor="nw",
            font=("Consolas", 11), fg=TEXT, bg=PANEL
        ).pack(anchor="w", padx=30, pady=25)

        tk.Button(
            panel, text="Retrain ML Models",
            command=self.retrain_models,
            bg="#145DA0", fg=WHITE, relief="flat", padx=14, pady=7
        ).pack(anchor="w", padx=30)

    def retrain_models(self):
        if not SKLEARN_AVAILABLE:
            messagebox.showwarning(
                "scikit-learn Missing",
                "Install scikit-learn with:\n\npip install scikit-learn"
            )
            return
        train_models()
        messagebox.showinfo("ML", "Random Forest and Isolation Forest retrained successfully.")
        self.show_ml()

    # ========================================================
    # ALERT CENTER
    # ========================================================

    def refresh_alert_badge(self):
        with db_connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE acknowledged=0"
            ).fetchone()[0]
        self.alert_badge.config(text=f"Unacknowledged Alerts: {count}")

    def alert_watcher(self):
        self.refresh_alert_badge()
        self.root.after(3000, self.alert_watcher)

    def show_alerts(self):
        self.current_page = "Alert Center"
        self.clear_content()
        self.page_title("Security Alert Center")

        panel = self.panel(self.content)
        panel.pack(fill="both", expand=True, padx=25, pady=15)

        cols = ("ID", "Time", "Level", "Threat ID", "Message", "Status")
        tree = ttk.Treeview(panel, columns=cols, show="headings")
        for c, w in zip(cols, (60, 150, 90, 75, 600, 100)):
            tree.heading(c, text=c)
            tree.column(c, width=w, anchor="center")
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        with db_connect() as conn:
            rows = conn.execute("""
                SELECT id, created_at, level, threat_id, message, acknowledged
                FROM alerts ORDER BY id DESC LIMIT 500
            """).fetchall()

        for r in rows:
            tree.insert(
                "", "end",
                values=(r[0], r[1], r[2], r[3], r[4],
                        "Acknowledged" if r[5] else "NEW")
            )

        def acknowledge():
            sel = tree.selection()
            if not sel:
                return
            aid = int(tree.item(sel[0])["values"][0])
            with db_connect() as conn:
                conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (aid,))
                conn.commit()
            self.show_alerts()

        tk.Button(
            panel, text="Acknowledge Selected Alert",
            command=acknowledge, bg="#075E54", fg=WHITE,
            relief="flat", padx=12, pady=7
        ).pack(anchor="w", padx=10, pady=8)

    # ========================================================
    # INCIDENT MANAGEMENT
    # ========================================================

    def create_incident_for(self, item, parent=None):
        with db_connect() as conn:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO incidents(
                    threat_id, title, description, status,
                    assigned_to, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?)
            """, (
                item["id"],
                f"{item['attack']} - {item['source_ip']}",
                f"Investigate {item['severity']} threat with risk {item['risk']}.",
                "Open", "admin", now, now
            ))
            iid = cur.lastrowid
            conn.execute("UPDATE threats SET incident_id=? WHERE id=?", (iid, item["id"]))
            conn.commit()

        messagebox.showinfo("Incident Created", f"Incident #{iid} created.")
        if parent:
            parent.destroy()

    def show_incidents(self):
        self.current_page = "Incidents"
        self.clear_content()
        self.page_title("Incident Management")

        top = tk.Frame(self.content, bg=BG)
        top.pack(fill="x", padx=25, pady=10)
        tk.Label(
            top, text="Track investigation lifecycle: Open → Investigating → Resolved",
            fg=MUTED, bg=BG
        ).pack(side="left")

        panel = self.panel(self.content)
        panel.pack(fill="both", expand=True, padx=25, pady=5)

        cols = ("ID", "Threat", "Title", "Status", "Assigned", "Created", "Updated")
        tree = ttk.Treeview(panel, columns=cols, show="headings")
        for c, w in zip(cols, (55, 65, 370, 110, 100, 150, 150)):
            tree.heading(c, text=c)
            tree.column(c, width=w, anchor="center")
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        with db_connect() as conn:
            rows = conn.execute("""
                SELECT id, threat_id, title, status, assigned_to, created_at, updated_at
                FROM incidents ORDER BY id DESC
            """).fetchall()

        for r in rows:
            tree.insert("", "end", values=r)

        def update_status():
            sel = tree.selection()
            if not sel:
                return
            iid = int(tree.item(sel[0])["values"][0])
            win = tk.Toplevel(self.root)
            win.title("Update Incident")
            win.geometry("320x180")
            win.configure(bg=BG)
            var = tk.StringVar(value="Investigating")
            ttk.Combobox(
                win, textvariable=var,
                values=["Open", "Investigating", "Resolved", "Closed"],
                state="readonly", width=20
            ).pack(pady=25)

            def save():
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with db_connect() as conn:
                    conn.execute(
                        "UPDATE incidents SET status=?, updated_at=? WHERE id=?",
                        (var.get(), now, iid)
                    )
                    conn.commit()
                win.destroy()
                self.show_incidents()

            tk.Button(
                win, text="SAVE", command=save,
                bg="#075E54", fg=WHITE, relief="flat", padx=15, pady=7
            ).pack()

        tk.Button(
            panel, text="Update Selected Incident",
            command=update_status, bg="#145DA0", fg=WHITE,
            relief="flat", padx=12, pady=7
        ).pack(anchor="w", padx=10, pady=8)

    # ========================================================
    # GLOBAL MAP
    # ========================================================

    def show_map(self):
        self.current_page = "Global Threat Map"
        self.clear_content()
        self.page_title("Global Cyber Threat Map")

        info = tk.Frame(self.content, bg=BG)
        info.pack(fill="x", padx=25, pady=8)

        data = get_all_threats()
        critical = sum(x["severity"] == "Critical" for x in data)
        high = sum(x["severity"] == "High" for x in data)

        tk.Label(
            info, text=f"GLOBAL THREAT ACTIVITY • {len(data)} EVENTS",
            font=("Segoe UI", 11, "bold"), fg=CYAN, bg=BG
        ).pack(side="left")
        tk.Label(
            info, text=f"● CRITICAL: {critical}",
            fg=RED, bg=BG, font=("Segoe UI", 9, "bold")
        ).pack(side="right", padx=10)
        tk.Label(
            info, text=f"● HIGH: {high}",
            fg=ORANGE, bg=BG, font=("Segoe UI", 9, "bold")
        ).pack(side="right", padx=10)

        canvas = tk.Canvas(
            self.content, bg="#020B13",
            highlightthickness=1, highlightbackground=BORDER
        )
        canvas.pack(fill="both", expand=True, padx=25, pady=8)

        def draw():
            canvas.delete("all")
            w = canvas.winfo_width()
            h = canvas.winfo_height()
            if w < 500 or h < 300:
                return

            for x in range(0, w, 40):
                canvas.create_line(x, 0, x, h, fill="#061B29")
            for y in range(0, h, 40):
                canvas.create_line(0, y, w, y, fill="#061B29")

            def xy(lon, lat):
                return (
                    35 + (lon + 180) / 360 * (w - 70),
                    45 + (90 - lat) / 180 * (h - 90)
                )

            # Stylized world silhouette using simple polygons.
            land = [
                [(-168,72),(-120,73),(-80,30),(-100,10),(-125,25)],
                [(-80,10),(-45,-5),(-55,-55),(-75,-25)],
                [(-10,70),(40,70),(100,65),(155,45),(135,10),(80,10),(40,30),(0,35)],
                [(-18,35),(40,30),(35,-30),(5,-35),(-15,0)],
                [(112,-10),(153,-25),(143,-40),(115,-30)]
            ]
            for poly in land:
                pts = []
                for lon, lat in poly:
                    px, py = xy(lon, lat)
                    pts += [px, py]
                canvas.create_polygon(
                    pts, fill="#071B27", outline="#0B526B", width=1
                )

            counts = {}
            for x in data:
                counts[x["country"]] = counts.get(x["country"], 0) + 1

            positions = {}
            for country, coord in COUNTRY_COORDS.items():
                positions[country] = xy(*coord)

            # Cyber routes
            routes = [
                ("USA", "India"), ("China", "USA"), ("India", "Germany"),
                ("UK", "Singapore"), ("Russia", "Australia")
            ]
            for a, b in routes:
                if a in positions and b in positions:
                    x1, y1 = positions[a]
                    x2, y2 = positions[b]
                    canvas.create_line(
                        x1, y1, x2, y2,
                        fill="#124C61", dash=(7, 5), width=2
                    )

            for country, (px, py) in positions.items():
                count = counts.get(country, 0)
                if count > 35:
                    color, radius = RED, 10
                elif count > 20:
                    color, radius = ORANGE, 8
                elif count > 0:
                    color, radius = CYAN, 6
                else:
                    color, radius = "#1B4354", 3

                canvas.create_oval(
                    px-radius, py-radius, px+radius, py+radius,
                    fill=color, outline=WHITE if count > 35 else ""
                )
                canvas.create_text(
                    px+12, py, text=f"{country} ({count})",
                    anchor="w", fill=TEXT, font=("Segoe UI", 8)
                )

            canvas.create_text(
                w/2, 22,
                text="CYBER ALLIANCE • GLOBAL THREAT NETWORK",
                fill=CYAN, font=("Segoe UI", 11, "bold")
            )

        canvas.bind("<Configure>", lambda _: draw())
        canvas.bind("<Button-1>", lambda e: self.map_click(e, canvas, data))

    def map_click(self, event, canvas, data):
        w, h = canvas.winfo_width(), canvas.winfo_height()
        def xy(lon, lat):
            return (
                35 + (lon + 180) / 360 * (w - 70),
                45 + (90 - lat) / 180 * (h - 90)
            )
        closest = None
        dist = 22
        for country, coord in COUNTRY_COORDS.items():
            x, y = xy(*coord)
            d = math.hypot(event.x-x, event.y-y)
            if d < dist:
                closest, dist = country, d
        if closest:
            events = [x for x in data if x["country"] == closest]
            critical = sum(x["severity"] == "Critical" for x in events)
            messagebox.showinfo(
                f"{closest} - Cyber Activity",
                f"Country: {closest}\n"
                f"Total Events: {len(events)}\n"
                f"Critical Events: {critical}\n"
                f"Average Risk: "
                f"{sum(x['risk'] for x in events)/len(events):.1f}"
                if events else f"Country: {closest}\nNo recorded events."
            )

    # ========================================================
    # SYSTEM
    # ========================================================

    def show_system(self):
        self.current_page = "System"
        self.clear_content()
        self.page_title("System Information")

        panel = self.panel(self.content)
        panel.pack(fill="both", expand=True, padx=30, pady=25)

        with db_connect() as conn:
            users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            threats = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
            incidents = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]

        text = (
            "🛡 CYBER SHIELD PLATFORM\n\n"
            "Project:\nCyber Security Threat Analysis & Monitoring System\n\n"
            "Programming Language:\nPython\n\n"
            "GUI Framework:\nTkinter\n\n"
            "Database:\nSQLite\n\n"
            f"Stored Threat Events:\n{threats}\n\n"
            f"Incidents:\n{incidents}\n\n"
            f"Users:\n{users}\n\n"
            "IMPLEMENTED FEATURES\n"
            "• Threat classification and risk scoring\n"
            "• Machine-learning severity prediction\n"
            "• Isolation Forest anomaly detection\n"
            "• Real-time simulated monitoring\n"
            "• Critical/High/Anomaly alerts\n"
            "• Alert acknowledgement history\n"
            "• Incident management\n"
            "• Global threat map\n"
            "• Search and advanced filtering\n"
            "• IP activity/reputation scoring\n"
            "• 24-hour threat trend analytics\n"
            "• CSV export\n"
            "• Professional PDF security report\n"
            "• Admin authentication\n\n"
            f"scikit-learn: {'AVAILABLE' if SKLEARN_AVAILABLE else 'NOT INSTALLED'}\n"
            f"ReportLab: {'AVAILABLE' if REPORTLAB_AVAILABLE else 'NOT INSTALLED'}\n\n"
            "STATUS: OPERATIONAL"
        )
        tk.Label(
            panel, text=text, justify="left", anchor="nw",
            font=("Consolas", 10), fg=TEXT, bg=PANEL
        ).pack(anchor="w", padx=45, pady=30)

        tk.Button(
            panel, text="Logout",
            command=self.logout, bg="#4A1825", fg=WHITE,
            relief="flat", padx=15, pady=7
        ).pack(anchor="w", padx=45)

    # ========================================================
    # CSV / PDF REPORTS
    # ========================================================

    def export_csv(self):
        data = self.filtered_data()
        if not data:
            messagebox.showwarning("Export", "No data available.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")]
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=THREAT_COLUMNS)
                writer.writeheader()
                writer.writerows(data)
            messagebox.showinfo("CSV Export", f"{len(data)} records exported.")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def export_pdf(self):
        if not REPORTLAB_AVAILABLE:
            messagebox.showwarning(
                "ReportLab Missing",
                "Install ReportLab with:\n\npip install reportlab"
            )
            return

        data = self.filtered_data()
        if not data:
            messagebox.showwarning("PDF Report", "No data available.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF Files", "*.pdf")]
        )
        if not path:
            return

        total = len(data)
        critical = sum(x["severity"] == "Critical" for x in data)
        high = sum(x["severity"] == "High" for x in data)
        anomalies = sum(x["anomaly"] for x in data)
        avg_risk = sum(x["risk"] for x in data) / total

        attacks = {}
        countries = {}
        for x in data:
            attacks[x["attack"]] = attacks.get(x["attack"], 0) + 1
            countries[x["country"]] = countries.get(x["country"], 0) + 1

        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate(path, pagesize=A4)
        story = [
            Paragraph("CYBER SHIELD - SECURITY INTELLIGENCE REPORT", styles["Title"]),
            Spacer(1, 12),
            Paragraph(
                f"Generated: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}",
                styles["Normal"]
            ),
            Spacer(1, 12)
        ]

        summary = [
            ["Metric", "Value"],
            ["Total Events", str(total)],
            ["Critical Events", str(critical)],
            ["High Events", str(high)],
            ["Anomalies", str(anomalies)],
            ["Average Risk", f"{avg_risk:.2f}/100"],
            ["Top Attack", max(attacks, key=attacks.get)],
            ["Top Country", max(countries, key=countries.get)]
        ]
        t = Table(summary, colWidths=[220, 220])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#12344A")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
            ("PADDING", (0,0), (-1,-1), 7)
        ]))
        story += [t, Spacer(1, 18)]

        story.append(Paragraph("Security Recommendations", styles["Heading2"]))
        for rec in [
            "Investigate Critical and High severity events first.",
            "Review repeated source IP addresses and high activity scores.",
            "Investigate events flagged as anomalies.",
            "Monitor privileged accounts and sensitive devices.",
            "Maintain firewall, IDS/IPS and endpoint security rules."
        ]:
            story.append(Paragraph("• " + rec, styles["Normal"]))
            story.append(Spacer(1, 5))

        story.append(Spacer(1, 12))
        story.append(Paragraph("Recent Threat Events", styles["Heading2"]))

        rows = [["ID", "Attack", "Severity", "Country", "Risk"]]
        for x in data[:20]:
            rows.append([
                str(x["id"]), x["attack"], x["severity"],
                x["country"], str(x["risk"])
            ])
        rt = Table(rows, colWidths=[45, 160, 80, 100, 55])
        rt.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#12344A")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("GRID", (0,0), (-1,-1), 0.4, colors.grey),
            ("FONTSIZE", (0,0), (-1,-1), 8),
            ("PADDING", (0,0), (-1,-1), 5)
        ]))
        story.append(rt)

        try:
            doc.build(story)
            messagebox.showinfo("PDF Report", "Professional security report generated.")
        except Exception as e:
            messagebox.showerror("PDF Error", str(e))

    # ========================================================
    # LIVE MODE
    # ========================================================

    def toggle_live(self):
        self.live_mode = not self.live_mode
        if self.live_mode:
            self.live_button.config(text="● LIVE: ON", fg=GREEN)
            self.live_monitor()
        else:
            self.live_button.config(text="○ LIVE: OFF", fg=MUTED)
            if self.live_job:
                try:
                    self.root.after_cancel(self.live_job)
                except Exception:
                    pass
                self.live_job = None

    def live_monitor(self):
        if not self.live_mode:
            return

        item = generate_raw_threat()
        tid = insert_threat(item)
        self.refresh_alert_badge()

        if self.current_page == "Dashboard":
            self.show_dashboard()
        elif self.current_page == "Threat Monitor":
            self.show_threats()
        elif self.current_page == "Security Analytics":
            self.show_analytics()
        elif self.current_page == "Alert Center":
            self.show_alerts()

        # Simulated real-time event every 5 seconds.
        self.live_job = self.root.after(5000, self.live_monitor)

    # ========================================================
    # LOGIN / LOGOUT
    # ========================================================

    def logout(self):
        self.live_mode = False
        self.root.destroy()


# ============================================================
# STARTUP
# ============================================================

def main():
    init_database()
    if SKLEARN_AVAILABLE:
        train_models()
    seed_database()

    root = tk.Tk()
    app = CyberShieldApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
