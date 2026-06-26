# NetSentinel — Architecture

[PCAP/Logs] → Suricata (EVE JSON)
│
├── parse_suricata.py ─┐
│ │
[PCAP/Logs] → Zeek (conn.log) │
│ ├─► visualization/alert_data.csv (normalized schema)
└── parse_zeek.py ─────┘
│
└─► src/netsentinel/correlator.py (time-window join on 5-tuple)
│
└─► src/netsentinel/detections/lateral_movement.py
│
├─► features + baseline ML score (model.pkl)
└─► dashboard.py (analytics)


**Normalized columns:** `timestamp, src_ip, src_port, dest_ip, dest_port, proto, severity, signature, category, engine`  
**Goal:** unify Suricata signatures with Zeek flows, correlate, then flag lateral-movement indicators (SMB/RDP pivots, high fan-out, new internal subnets).
