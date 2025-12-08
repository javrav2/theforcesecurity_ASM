'use client';

import React, { useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { MapPin, Globe, AlertTriangle } from 'lucide-react';

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
  type: string;
  findingsCount: number;
  geoLocation?: GeoLocation;
}

interface WorldMapProps {
  assets: Asset[];
  onAssetClick?: (asset: Asset) => void;
}

// SVG World Map paths - simplified continents
const worldMapPaths = {
  // North America
  northAmerica: "M 80 60 Q 120 40 180 50 Q 220 45 240 80 Q 220 120 180 130 Q 140 140 100 120 Q 60 100 80 60",
  // South America
  southAmerica: "M 150 160 Q 180 150 190 180 Q 200 230 180 280 Q 160 300 140 280 Q 130 240 140 200 Q 145 170 150 160",
  // Europe
  europe: "M 280 50 Q 320 40 350 55 Q 370 70 360 90 Q 340 100 300 95 Q 270 90 280 50",
  // Africa
  africa: "M 280 110 Q 330 100 350 130 Q 360 180 340 230 Q 300 250 270 230 Q 250 180 260 140 Q 270 120 280 110",
  // Asia
  asia: "M 360 40 Q 450 30 520 60 Q 550 100 520 140 Q 470 160 420 150 Q 380 140 370 100 Q 360 70 360 40",
  // Australia
  australia: "M 480 200 Q 530 190 550 210 Q 560 240 540 260 Q 500 270 480 250 Q 470 220 480 200",
};

export function WorldMap({ assets, onAssetClick }: WorldMapProps) {
  const geoAssets = useMemo(
    () => assets.filter(asset => asset.geoLocation),
    [assets]
  );

  // Group assets by approximate region
  const regionData = useMemo(() => {
    const regions: Record<string, { count: number; findings: number; assets: Asset[] }> = {
      'North America': { count: 0, findings: 0, assets: [] },
      'South America': { count: 0, findings: 0, assets: [] },
      'Europe': { count: 0, findings: 0, assets: [] },
      'Africa': { count: 0, findings: 0, assets: [] },
      'Asia': { count: 0, findings: 0, assets: [] },
      'Australia': { count: 0, findings: 0, assets: [] },
    };

    geoAssets.forEach(asset => {
      const lat = asset.geoLocation!.latitude;
      const lon = asset.geoLocation!.longitude;
      
      let region = 'Asia';
      if (lon < -30 && lat > 0) region = 'North America';
      else if (lon < -30 && lat <= 0) region = 'South America';
      else if (lon >= -30 && lon < 60 && lat > 35) region = 'Europe';
      else if (lon >= -30 && lon < 60 && lat <= 35) region = 'Africa';
      else if (lon >= 100 && lat < 0) region = 'Australia';
      
      regions[region].count++;
      regions[region].findings += asset.findingsCount;
      regions[region].assets.push(asset);
    });

    return regions;
  }, [geoAssets]);

  const getRegionColor = (region: string) => {
    const data = regionData[region];
    if (!data || data.count === 0) return 'fill-muted/30';
    if (data.findings > 10) return 'fill-red-500/60';
    if (data.findings > 5) return 'fill-orange-500/50';
    if (data.findings > 0) return 'fill-yellow-500/40';
    return 'fill-green-500/40';
  };

  // Convert lat/lon to SVG coordinates
  const geoToSvg = (lat: number, lon: number) => {
    // Simple equirectangular projection
    const x = (lon + 180) * (600 / 360);
    const y = (90 - lat) * (300 / 180);
    return { x, y };
  };

  const getMarkerColor = (findingsCount: number) => {
    if (findingsCount > 5) return 'fill-red-500';
    if (findingsCount > 2) return 'fill-orange-500';
    if (findingsCount > 0) return 'fill-yellow-500';
    return 'fill-green-500';
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
          <svg
            viewBox="0 0 600 300"
            className="w-full h-full"
            preserveAspectRatio="xMidYMid meet"
          >
            {/* Background grid */}
            <defs>
              <pattern id="grid" width="30" height="30" patternUnits="userSpaceOnUse">
                <path
                  d="M 30 0 L 0 0 0 30"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="0.5"
                  className="text-border/30"
                />
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#grid)" />

            {/* Continents */}
            <g className="transition-all duration-300">
              <path
                d={worldMapPaths.northAmerica}
                className={`${getRegionColor('North America')} stroke-border transition-colors hover:opacity-80`}
                strokeWidth="1"
              />
              <path
                d={worldMapPaths.southAmerica}
                className={`${getRegionColor('South America')} stroke-border transition-colors hover:opacity-80`}
                strokeWidth="1"
              />
              <path
                d={worldMapPaths.europe}
                className={`${getRegionColor('Europe')} stroke-border transition-colors hover:opacity-80`}
                strokeWidth="1"
              />
              <path
                d={worldMapPaths.africa}
                className={`${getRegionColor('Africa')} stroke-border transition-colors hover:opacity-80`}
                strokeWidth="1"
              />
              <path
                d={worldMapPaths.asia}
                className={`${getRegionColor('Asia')} stroke-border transition-colors hover:opacity-80`}
                strokeWidth="1"
              />
              <path
                d={worldMapPaths.australia}
                className={`${getRegionColor('Australia')} stroke-border transition-colors hover:opacity-80`}
                strokeWidth="1"
              />
            </g>

            {/* Asset markers */}
            {geoAssets.map((asset) => {
              const { x, y } = geoToSvg(
                asset.geoLocation!.latitude,
                asset.geoLocation!.longitude
              );
              return (
                <g
                  key={asset.id}
                  className="cursor-pointer transition-transform hover:scale-150"
                  onClick={() => onAssetClick?.(asset)}
                >
                  <circle
                    cx={x}
                    cy={y}
                    r={asset.findingsCount > 0 ? 5 : 3}
                    className={`${getMarkerColor(asset.findingsCount)} stroke-background`}
                    strokeWidth="1.5"
                    opacity="0.9"
                  >
                    <title>
                      {asset.value}
                      {asset.geoLocation?.city && `\n${asset.geoLocation.city}, ${asset.geoLocation.country}`}
                      {`\n${asset.findingsCount} finding${asset.findingsCount !== 1 ? 's' : ''}`}
                    </title>
                  </circle>
                  {asset.findingsCount > 5 && (
                    <circle
                      cx={x}
                      cy={y}
                      r={8}
                      className="fill-none stroke-red-500 animate-ping"
                      strokeWidth="1"
                      opacity="0.5"
                    />
                  )}
                </g>
              );
            })}
          </svg>

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



