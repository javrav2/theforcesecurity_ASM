#!/usr/bin/env python3
"""Script to check geo data status in the database."""

from app.db.database import SessionLocal
from app.models.asset import Asset, AssetType
from sqlalchemy import func

db = SessionLocal()

# Total assets
total = db.query(Asset).count()
print(f"Total assets: {total}")

# Assets with latitude
with_lat = db.query(Asset).filter(Asset.latitude != None, Asset.latitude != '').count()
print(f"Assets with latitude: {with_lat}")

# Assets with longitude
with_lon = db.query(Asset).filter(Asset.longitude != None, Asset.longitude != '').count()
print(f"Assets with longitude: {with_lon}")

# Assets with both lat and lon
with_both = db.query(Asset).filter(
    Asset.latitude != None, Asset.latitude != '',
    Asset.longitude != None, Asset.longitude != ''
).count()
print(f"Assets with both lat AND lon: {with_both}")

# Assets with country
with_country = db.query(Asset).filter(Asset.country != None, Asset.country != '').count()
print(f"Assets with country: {with_country}")

# Assets with city
with_city = db.query(Asset).filter(Asset.city != None, Asset.city != '').count()
print(f"Assets with city: {with_city}")

# Assets with IP address
with_ip = db.query(Asset).filter(Asset.ip_address != None, Asset.ip_address != '').count()
print(f"Assets with IP address: {with_ip}")

# Check a sample of assets with geo data
print("\n--- Sample assets with geo data ---")
samples = db.query(Asset).filter(
    Asset.latitude != None, Asset.latitude != ''
).limit(5).all()

for a in samples:
    print(f"{a.value}: lat={a.latitude}, lon={a.longitude}, country={a.country}, city={a.city}")

# Check sample without geo data
print("\n--- Sample assets WITHOUT geo data ---")
samples_no_geo = db.query(Asset).filter(
    (Asset.latitude == None) | (Asset.latitude == '')
).limit(5).all()

for a in samples_no_geo:
    print(f"{a.value}: ip={a.ip_address}, type={a.asset_type}")

db.close()
