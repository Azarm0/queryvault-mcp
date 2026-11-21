"""Deterministic SaaS demo SQLite database generator for QueryVault MCP."""

from __future__ import annotations

import random
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE customers (
    id INTEGER PRIMARY KEY,
    company_name TEXT NOT NULL,
    contact_email TEXT NOT NULL,
    phone TEXT NOT NULL,
    plan_tier TEXT NOT NULL,
    api_key TEXT NOT NULL,
    country TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_customers_plan_tier ON customers(plan_tier);

CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    amount_usd REAL NOT NULL,
    status TEXT NOT NULL,
    region TEXT NOT NULL,
    notes TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_orders_customer_id ON orders(customer_id);
-- Intentionally no index on orders(status) or orders(region) so explain_query_plan
-- demonstrates full table SCAN detection and index recommendations.

CREATE TABLE subscriptions (
    id INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    mrr_usd REAL NOT NULL,
    status TEXT NOT NULL,
    renewal_date TEXT NOT NULL
);

CREATE INDEX idx_subscriptions_customer_id ON subscriptions(customer_id);

CREATE TABLE webhook_events (
    id INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    event_type TEXT NOT NULL,
    http_status INTEGER NOT NULL,
    payload TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

_COMPANIES = [
    ("Northstar Analytics", "alice.chen@northstar.io", "+1-415-555-0142", "enterprise", "US"),
    ("Kestrel Cloud", "marcus.reed@kestrelcloud.com", "+1-212-555-0198", "growth", "US"),
    ("Verve Logistics", "elena.rossi@vervelogistics.eu", "+44-207-555-0131", "growth", "UK"),
    ("Bosphorus FinTech", "kerem.yilmaz@bosphorusfin.tr", "+90-212-555-0184", "enterprise", "TR"),
    ("Pinecone Labs", "priya.nair@pineconelabs.dev", "+1-650-555-0117", "starter", "US"),
    ("Cobalt Metrics", "lukas.weber@cobaltmetrics.de", "+49-301-555-0165", "growth", "DE"),
    ("Helios Commerce", "sofia.mendez@helioscommerce.co", "+1-305-555-0129", "starter", "US"),
    ("Redwood Security", "david.kim@redwoodsec.io", "+1-408-555-0173", "enterprise", "US"),
    ("Aurora Health", "hannah.brooks@aurorahealth.org", "+1-617-555-0156", "growth", "US"),
    ("Fjord Robotics", "henrik.lind@fjordrobotics.no", "+47-210-555-0148", "starter", "NO"),
    ("Meridian Freight", "tariq.hassan@meridianfreight.ae", "+971-455-555-0190", "growth", "AE"),
    ("Stratos AI", "chloe.dubois@stratosai.fr", "+33-142-555-0112", "enterprise", "FR"),
    ("Quartz Retail", "oliver.grant@quartzretail.co.uk", "+44-161-555-0177", "starter", "UK"),
    ("Tundra Data", "mika.korhonen@tundradata.fi", "+358-405-555-0139", "growth", "FI"),
    ("Veridian Ops", "nina.patel@veridianops.com", "+1-512-555-0162", "enterprise", "US"),
]


def seed_demo_database(db_path: Path | str, force: bool = False) -> Path:
    """Create a deterministic SaaS demo SQLite database with PII and seeded anomalies."""
    target = Path(db_path).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)

    if target.exists():
        if not force:
            return target
        target.unlink()

    rng = random.Random(42)
    base_time = datetime(2026, 9, 1, 9, 0, 0, tzinfo=UTC)

    conn = sqlite3.connect(target)
    try:
        conn.executescript(SCHEMA_SQL)

        customers_rows = []
        for idx, (company, email, phone, tier, country) in enumerate(_COMPANIES, start=1):
            created = (base_time - timedelta(days=180 - idx * 7)).isoformat()
            api_key = f"qv_live_{idx:02d}_{rng.randrange(10**12, 10**13 - 1)}"
            customers_rows.append((idx, company, email, phone, tier, api_key, country, created))

        conn.executemany(
            "INSERT INTO customers "
            "(id, company_name, contact_email, phone, plan_tier, api_key, country, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            customers_rows,
        )

        # 120 orders so limit=100 truncation is exercised, with 2 deliberate billing anomalies.
        regions = ["us-east", "us-west", "eu-central", "eu-west", "ap-south"]
        statuses = ["paid", "paid", "paid", "paid", "pending", "failed"]
        orders_rows = []
        for order_id in range(1, 121):
            cust_id = rng.randint(1, len(_COMPANIES))
            region = rng.choice(regions)
            status = rng.choice(statuses)
            created = (base_time + timedelta(hours=order_id * 11)).isoformat()

            if order_id == 47:
                amount = 14950.00
                status = "paid"
                notes = "Duplicate enterprise annual invoice retry - escalate to billing@northstar.io"
            elif order_id == 93:
                amount = 9800.00
                status = "failed"
                notes = "Payment gateway retry storm; customer callback +1-415-555-0199"
            else:
                amount = round(rng.uniform(49.0, 499.0), 2)
                notes = f"Standard invoice batch #{order_id:03d}"

            orders_rows.append((order_id, cust_id, amount, status, region, notes, created))

        conn.executemany(
            "INSERT INTO orders "
            "(id, customer_id, amount_usd, status, region, notes, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            orders_rows,
        )

        tier_mrr = {"starter": 99.0, "growth": 349.0, "enterprise": 1250.0}
        sub_rows = []
        for sub_id in range(1, 21):
            cust_id = ((sub_id - 1) % len(_COMPANIES)) + 1
            tier = _COMPANIES[cust_id - 1][3]
            mrr = tier_mrr[tier]
            sub_status = "past_due" if sub_id in (6, 14) else "active"
            renewal = (base_time + timedelta(days=30 + sub_id * 2)).date().isoformat()
            sub_rows.append((sub_id, cust_id, mrr, sub_status, renewal))

        conn.executemany(
            "INSERT INTO subscriptions (id, customer_id, mrr_usd, status, renewal_date) "
            "VALUES (?, ?, ?, ?, ?)",
            sub_rows,
        )

        event_types = [
            "invoice.paid",
            "invoice.payment_failed",
            "subscription.updated",
            "customer.updated",
        ]
        webhook_rows = []
        for ev_id in range(1, 36):
            cust_id = ((ev_id - 1) % len(_COMPANIES)) + 1
            email = _COMPANIES[cust_id - 1][1]
            phone = _COMPANIES[cust_id - 1][2]
            ev_type = event_types[ev_id % len(event_types)]
            http_status = 500 if ev_id in (9, 17, 25) else 200
            payload = (
                f'{{"event":"{ev_type}","customer_id":{cust_id},'
                f'"notify":"{email}","support_phone":"{phone}"}}'
            )
            created = (base_time + timedelta(hours=ev_id * 6)).isoformat()
            webhook_rows.append((ev_id, cust_id, ev_type, http_status, payload, created))

        conn.executemany(
            "INSERT INTO webhook_events "
            "(id, customer_id, event_type, http_status, payload, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            webhook_rows,
        )

        conn.commit()
    finally:
        conn.close()

    return target
