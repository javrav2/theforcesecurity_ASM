#!/bin/bash
# Diagnose Critical Port Monitoring Issues
# Run this on your AWS instance

echo "=== 1. Check Scanner Container Logs ==="
docker logs asm_scanner 2>&1 | tail -100

echo ""
echo "=== 2. Check if Masscan is installed and working ==="
docker exec asm_scanner which masscan
docker exec asm_scanner masscan --version

echo ""
echo "=== 3. Test Masscan with a simple scan (should need root) ==="
docker exec asm_scanner masscan 8.8.8.8 -p53 --rate=100 --wait=2

echo ""
echo "=== 4. Check Recent Scans in Database ==="
docker exec asm_backend python -c "
from app.db.database import SessionLocal
from app.models.scan import Scan

db = SessionLocal()
scans = db.query(Scan).order_by(Scan.id.desc()).limit(5).all()
for s in scans:
    print(f'Scan {s.id}: {s.name}')
    print(f'  Status: {s.status}, Type: {s.scan_type}')
    print(f'  Targets: {len(s.targets) if s.targets else 0}')
    print(f'  Results: {s.results}')
    print(f'  Error: {s.error_message}')
    print()
db.close()
"

echo ""
echo "=== 5. Check In-Scope IPv4 Netblocks ==="
docker exec asm_backend python -c "
from app.db.database import SessionLocal
from app.models.netblock import Netblock

db = SessionLocal()
netblocks = db.query(Netblock).filter(
    Netblock.in_scope == True,
    Netblock.ip_version == 'ipv4'
).all()
print(f'Found {len(netblocks)} in-scope IPv4 netblocks:')
for nb in netblocks[:10]:
    print(f'  {nb.cidr_notation} - {nb.ip_count} IPs - Org: {nb.organization_id}')
db.close()
"

echo ""
echo "=== 6. Check Schedule Worker Logs ==="
docker logs asm_scheduler 2>&1 | tail -50

echo ""
echo "=== 7. Check Critical Ports Schedule ==="
docker exec asm_backend python -c "
from app.db.database import SessionLocal
from app.models.scan_schedule import ScanSchedule

db = SessionLocal()
schedules = db.query(ScanSchedule).filter(
    ScanSchedule.scan_type == 'critical_ports'
).all()
print(f'Found {len(schedules)} critical_ports schedules:')
for s in schedules:
    print(f'  ID {s.id}: {s.name}')
    print(f'    Enabled: {s.is_enabled}, Failures: {s.consecutive_failures}')
    print(f'    Last Error: {s.last_error}')
    print(f'    Next Run: {s.next_run_at}')
    print(f'    Config: {s.config}')
    print()
db.close()
"
