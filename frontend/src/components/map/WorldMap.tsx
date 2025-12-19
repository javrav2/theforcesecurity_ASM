'use client';

import React, { useMemo } from 'react';
import { ComposableMap, Geographies, Geography, Marker } from 'react-simple-maps';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { MapPin, Globe, AlertTriangle } from 'lucide-react';

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
  findingsCount: number;
  geoLocation?: GeoLocation;
}

interface WorldMapProps {
  assets: Asset[];
  onAssetClick?: (asset: Asset) => void;
}

export function WorldMap({ assets, onAssetClick }: WorldMapProps) {
  const geoAssets = useMemo(
    () => assets.filter(asset => asset.geoLocation),
    [assets]
  );

  // Group assets by country for heatmap effect
  const countryData = useMemo(() => {
    const counts: Record<string, number> = {};
    geoAssets.forEach(asset => {
      const code = asset.geoLocation?.countryCode || 'Unknown';
      counts[code] = (counts[code] || 0) + 1;
    });
    return counts;
  }, [geoAssets]);

  const getCountryFill = (geo: any) => {
    // Try different country code formats
    const id = geo.id || geo.properties?.ISO_A2 || geo.properties?.ISO_A3;
    const count = countryData[id] || 0;
    
    if (count === 0) return "hsl(220 20% 20%)"; // Dark background for empty
    if (count >= 5) return "hsl(0 84% 60%)";    // Red - critical
    if (count >= 3) return "hsl(25 95% 53%)";   // Orange - high  
    if (count >= 1) return "hsl(48 96% 53%)";   // Yellow - medium
    return "hsl(142 76% 36%)";                   // Green - low
  };

  const getMarkerColor = (findingsCount: number) => {
    if (findingsCount > 5) return "hsl(0 84% 60%)";     // Red
    if (findingsCount > 2) return "hsl(25 95% 53%)";    // Orange
    if (findingsCount > 0) return "hsl(48 96% 53%)";    // Yellow
    return "hsl(142 76% 36%)";                           // Green
  };

  const getMarkerSize = (findingsCount: number) => {
    if (findingsCount > 5) return 8;
    if (findingsCount > 2) return 6;
    return 4;
  };

  return (
    <Card className="bg-card border-border">
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm font-medium text-foreground flex items-center gap-2">
          <MapPin className="h-4 w-4 text-primary" />
          Global Attack Surface Heatmap
        </CardTitle>
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-red-500"></span>
            <span className="text-muted-foreground">Critical</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-orange-500"></span>
            <span className="text-muted-foreground">High</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-yellow-500"></span>
            <span className="text-muted-foreground">Medium</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-green-500"></span>
            <span className="text-muted-foreground">Safe</span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="relative h-[350px] rounded-b-lg overflow-hidden bg-background/50">
          <ComposableMap
            projection="geoMercator"
            projectionConfig={{
              scale: 140,
              center: [0, 30],
            }}
            className="w-full h-full"
            style={{ width: '100%', height: '100%' }}
          >
            <Geographies geography={geoUrl}>
              {({ geographies }) =>
                geographies.map((geo) => (
                  <Geography
                    key={geo.rsmKey}
                    geography={geo}
                    fill={getCountryFill(geo)}
                    stroke="hsl(220 20% 30%)"
                    strokeWidth={0.5}
                    style={{
                      default: { outline: "none" },
                      hover: { outline: "none", fill: "hsl(217 91% 60%)", cursor: "pointer" },
                      pressed: { outline: "none" },
                    }}
                  />
                ))
              }
            </Geographies>
            {geoAssets.map((asset) => (
              <Marker
                key={asset.id}
                coordinates={[asset.geoLocation!.longitude, asset.geoLocation!.latitude]}
                onClick={() => onAssetClick?.(asset)}
              >
                <g transform={`translate(-${getMarkerSize(asset.findingsCount)}, -${getMarkerSize(asset.findingsCount)})`}>
                  <circle
                    r={getMarkerSize(asset.findingsCount)}
                    fill={getMarkerColor(asset.findingsCount)}
                    stroke="hsl(0 0% 10%)"
                    strokeWidth={1.5}
                    opacity={0.9}
                  />
                  {asset.findingsCount > 5 && (
                    <circle
                      r={getMarkerSize(asset.findingsCount) + 4}
                      fill="none"
                      stroke={getMarkerColor(asset.findingsCount)}
                      strokeWidth={1}
                      opacity={0.5}
                      className="animate-ping"
                    />
                  )}
                  <title>
                    {asset.value}
                    {asset.geoLocation?.city && `\n${asset.geoLocation.city}, ${asset.geoLocation.country}`}
                    {`\n${asset.findingsCount} finding${asset.findingsCount !== 1 ? 's' : ''}`}
                  </title>
                </g>
              </Marker>
            ))}
          </ComposableMap>

          {/* Stats overlay */}
          <div className="absolute bottom-2 left-2 text-xs text-muted-foreground bg-background/80 px-2 py-1 rounded flex items-center gap-2">
            <Globe className="h-3 w-3" />
            {geoAssets.length} geolocated asset{geoAssets.length !== 1 ? 's' : ''}
          </div>

          {/* Alert count */}
          {geoAssets.filter(a => a.findingsCount > 0).length > 0 && (
            <div className="absolute bottom-2 right-2 text-xs bg-red-500/10 text-red-400 px-2 py-1 rounded flex items-center gap-1">
              <AlertTriangle className="h-3 w-3" />
              {geoAssets.filter(a => a.findingsCount > 0).length} with findings
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

export default WorldMap;

