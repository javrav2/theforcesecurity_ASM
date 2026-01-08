'use client';

import React, { useMemo, useState } from 'react';
import { ComposableMap, Geographies, Geography, Marker, ZoomableGroup } from 'react-simple-maps';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { MapPin, Globe, Building2, Server } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

const geoUrl = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

interface GeoLocation {
  latitude: number;
  longitude: number;
  city?: string;
  country?: string;
  countryCode?: string;
}

interface Asset {
  id: number;
  value: string;
  type?: string;
  findingsCount?: number;
  geoLocation?: GeoLocation;
}

interface WorldMapProps {
  assets: Asset[];
  onAssetClick?: (asset: Asset) => void;
}

// Country code mapping for common mismatches
const countryCodeMap: Record<string, string> = {
  'USA': 'US',
  'GBR': 'GB',
  'DEU': 'DE',
  'FRA': 'FR',
  'CAN': 'CA',
  'AUS': 'AU',
  'JPN': 'JP',
  'CHN': 'CN',
  'IND': 'IN',
  'BRA': 'BR',
};

export function WorldMap({ assets, onAssetClick }: WorldMapProps) {
  const [hoveredCountry, setHoveredCountry] = useState<string | null>(null);
  const [position, setPosition] = useState({ coordinates: [0, 20] as [number, number], zoom: 1 });

  const geoAssets = useMemo(
    () => assets.filter(asset => asset.geoLocation?.latitude && asset.geoLocation?.longitude),
    [assets]
  );

  // Group assets by country for coloring
  const countryData = useMemo(() => {
    const data: Record<string, { count: number; assets: Asset[]; country: string }> = {};
    geoAssets.forEach(asset => {
      let code = asset.geoLocation?.countryCode || 'Unknown';
      // Normalize country code
      if (countryCodeMap[code]) code = countryCodeMap[code];
      
      if (!data[code]) {
        data[code] = { count: 0, assets: [], country: asset.geoLocation?.country || 'Unknown' };
      }
      data[code].count += 1;
      data[code].assets.push(asset);
    });
    return data;
  }, [geoAssets]);

  // Get top countries by asset count
  const topCountries = useMemo(() => {
    return Object.entries(countryData)
      .map(([code, data]) => ({ code, ...data }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);
  }, [countryData]);

  // Get unique countries count
  const uniqueCountries = Object.keys(countryData).length;

  const getCountryFill = (geo: any) => {
    // Try different country code formats
    const geoId = geo.id;
    const iso2 = geo.properties?.ISO_A2;
    const iso3 = geo.properties?.ISO_A3;
    
    // Check various formats
    const count = countryData[geoId]?.count || 
                  countryData[iso2]?.count || 
                  countryData[iso3]?.count ||
                  countryData[countryCodeMap[geoId]]?.count ||
                  0;
    
    const isHovered = hoveredCountry === geoId || hoveredCountry === iso2 || hoveredCountry === iso3;
    
    if (isHovered) return "hsl(217 91% 60%)"; // Bright blue on hover
    
    if (count === 0) return "hsl(220 15% 18%)"; // Dark gray for no assets
    if (count >= 20) return "hsl(199 89% 48%)"; // Bright cyan - many assets
    if (count >= 10) return "hsl(199 80% 40%)"; // Cyan
    if (count >= 5) return "hsl(199 70% 35%)";  // Medium cyan
    if (count >= 2) return "hsl(199 60% 30%)";  // Lighter
    return "hsl(199 50% 25%)";                   // Light cyan - few assets
  };

  const getMarkerColor = (assetType?: string) => {
    switch (assetType?.toLowerCase()) {
      case 'domain':
        return "hsl(142 76% 45%)"; // Green
      case 'subdomain':
        return "hsl(199 89% 48%)"; // Cyan
      case 'ip_address':
        return "hsl(280 80% 60%)"; // Purple
      default:
        return "hsl(48 96% 53%)"; // Yellow
    }
  };

  const handleMoveEnd = (position: any) => {
    setPosition(position);
  };

  return (
    <Card className="bg-card border-border">
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium text-foreground flex items-center gap-2">
          <Globe className="h-4 w-4 text-cyan-400" />
          Global Asset Distribution
        </CardTitle>
        <div className="flex items-center gap-3 text-xs">
          <div className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-green-500"></span>
            <span className="text-muted-foreground">Domain</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
            <span className="text-muted-foreground">Subdomain</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-purple-500"></span>
            <span className="text-muted-foreground">IP</span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="relative h-[400px] rounded-b-lg overflow-hidden bg-slate-950">
          <ComposableMap
            projection="geoMercator"
            projectionConfig={{
              scale: 140,
              center: [0, 30],
            }}
            className="w-full h-full"
            style={{ width: '100%', height: '100%' }}
          >
            <ZoomableGroup
              zoom={position.zoom}
              center={position.coordinates}
              onMoveEnd={handleMoveEnd}
            >
              <Geographies geography={geoUrl}>
                {({ geographies }) =>
                  geographies.map((geo) => {
                    const geoId = geo.id;
                    const iso2 = geo.properties?.ISO_A2;
                    const count = countryData[geoId]?.count || 
                                  countryData[iso2]?.count || 
                                  countryData[countryCodeMap[geoId]]?.count || 0;
                    
                    return (
                      <Geography
                        key={geo.rsmKey}
                        geography={geo}
                        fill={getCountryFill(geo)}
                        stroke="hsl(220 20% 25%)"
                        strokeWidth={0.5}
                        onMouseEnter={() => setHoveredCountry(geoId)}
                        onMouseLeave={() => setHoveredCountry(null)}
                        style={{
                          default: { outline: "none", transition: "fill 0.2s" },
                          hover: { outline: "none", cursor: count > 0 ? "pointer" : "default" },
                          pressed: { outline: "none" },
                        }}
                      />
                    );
                  })
                }
              </Geographies>
              
              {/* Asset markers */}
              {geoAssets.map((asset) => (
                <Marker
                  key={asset.id}
                  coordinates={[asset.geoLocation!.longitude, asset.geoLocation!.latitude]}
                  onClick={() => onAssetClick?.(asset)}
                >
                  <g style={{ cursor: 'pointer' }}>
                    <circle
                      r={4 / position.zoom}
                      fill={getMarkerColor(asset.type)}
                      stroke="hsl(0 0% 100%)"
                      strokeWidth={1 / position.zoom}
                      opacity={0.9}
                    />
                    <title>
                      {asset.value}
                      {asset.geoLocation?.city && `\n📍 ${asset.geoLocation.city}, ${asset.geoLocation.country}`}
                      {asset.type && `\n🏷️ ${asset.type}`}
                    </title>
                  </g>
                </Marker>
              ))}
            </ZoomableGroup>
          </ComposableMap>

          {/* Stats overlay - bottom left */}
          <div className="absolute bottom-3 left-3 flex flex-col gap-2">
            <div className="text-xs bg-slate-900/90 backdrop-blur px-3 py-2 rounded-lg border border-slate-700">
              <div className="flex items-center gap-2 text-slate-200 font-medium mb-1">
                <MapPin className="h-3 w-3 text-cyan-400" />
                {geoAssets.length} Assets Mapped
              </div>
              <div className="text-slate-400">
                across {uniqueCountries} {uniqueCountries === 1 ? 'country' : 'countries'}
              </div>
            </div>
          </div>

          {/* Top countries - bottom right */}
          {topCountries.length > 0 && (
            <div className="absolute bottom-3 right-3 text-xs bg-slate-900/90 backdrop-blur px-3 py-2 rounded-lg border border-slate-700 max-w-[200px]">
              <div className="flex items-center gap-2 text-slate-200 font-medium mb-2">
                <Building2 className="h-3 w-3 text-cyan-400" />
                Top Locations
              </div>
              <div className="space-y-1">
                {topCountries.map((c, i) => (
                  <div key={c.code} className="flex justify-between items-center text-slate-300">
                    <span className="truncate">{c.country}</span>
                    <Badge variant="secondary" className="ml-2 text-xs px-1.5 py-0 h-5 bg-cyan-500/20 text-cyan-300 border-0">
                      {c.count}
                    </Badge>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Zoom controls hint */}
          <div className="absolute top-3 right-3 text-xs text-slate-500">
            Scroll to zoom • Drag to pan
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default WorldMap;
