import React, { useState, useEffect, useRef, useMemo } from 'react';
import ReactDOM from 'react-dom/client';
import { GoogleGenAI, Type } from '@google/genai';
import './index.css';

// Type Definitions
type Status = 'Secure' | 'Scanning' | 'Threat Found';
type LogType = 'INFO' | 'WARNING' | 'ERROR';

type ThreatDetails = {
  id: string;
  threatType: string;
  sourceIp: string;
  severity: 'High' | 'Critical';
  origin: string;
  recommendation: string;
  isRemediable?: boolean;
  remediationAction?: string;
  remediated?: boolean;
};

type LogEntry = {
  id: string;
  timestamp: string;
  type: LogType;
  message: string;
  sourceIp: string;
  details?: ThreatDetails;
};

// --- Mock Data and Simulation ---

const FAKE_IPS = [
  '203.0.113.1', '198.51.100.2', '192.0.2.3', '8.8.8.8',
  '1.1.1.1', '104.16.132.229', '172.67.149.54', '23.227.38.32'
];

const UNAUTHORIZED_IPS = ['10.255.255.1', '192.168.1.101', '172.16.31.50'];


const THREAT_TYPES = {
  'DDoS': 'Distributed Denial of Service attack detected.',
  'Malware': 'Malware signature detected in network traffic.',
  'Phishing': 'Phishing attempt from a known malicious domain.',
  'SQL Injection': 'Potential SQL injection attack against database server.'
};

const THREAT_ORIGINS = ['North Korea', 'Russia', 'China', 'USA', 'Brazil', 'Germany'];

const generateRandomLog = (threatPossible: boolean): LogEntry => {
  const id = `log-${Date.now()}-${Math.random()}`;
  const timestamp = new Date().toLocaleTimeString();
  const sourceIp = FAKE_IPS[Math.floor(Math.random() * FAKE_IPS.length)];

  if (threatPossible && Math.random() < 0.2) {
    const threatKeys = Object.keys(THREAT_TYPES);
    const threatType = threatKeys[Math.floor(Math.random() * threatKeys.length)];
    const severity = Math.random() > 0.3 ? 'Critical' : 'High';
    const threatDetails: ThreatDetails = {
      id: `threat-${Date.now()}`,
      threatType,
      sourceIp,
      severity,
      origin: THREAT_ORIGINS[Math.floor(Math.random() * THREAT_ORIGINS.length)],
      recommendation: `Isolate the source IP (${sourceIp}) and patch the vulnerable service.`,
      isRemediable: true,
      remediationAction: `Block IP ${sourceIp} in firewall.`
    };
    return {
      id,
      timestamp,
      type: 'ERROR',
      message: `${threatType} detected`,
      sourceIp,
      details: threatDetails
    };
  }
  
  if (Math.random() < 0.05) { // 5% chance of unauthorized access attempt
    return {
        id,
        timestamp,
        type: 'WARNING',
        message: 'Unauthorized access attempt from new device.',
        sourceIp: UNAUTHORIZED_IPS[Math.floor(Math.random() * UNAUTHORIZED_IPS.length)],
    };
  }

  return {
    id,
    timestamp,
    type: 'INFO',
    message: 'Normal traffic packet processed.',
    sourceIp,
  };
};

// --- API Client ---
const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });

// --- Components ---

const Logo = () => (
    <svg className="logo" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M24 4L6 14V26C6 34.83 13.63 42.43 24 44C34.37 42.43 42 34.83 42 26V14L24 4Z" fill="var(--logo-fill-color)"/>
        <path d="M24 4L6 14V26C6 34.83 13.63 42.43 24 44C34.37 42.43 42 34.83 42 26V14L24 4Z" stroke="var(--logo-stroke-color)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"/>
        <path d="M24 20V32" stroke="var(--logo-stroke-color)" strokeWidth="1.5" strokeLinecap="round"/>
        <path d="M18 23L30 23" stroke="var(--logo-stroke-color)" strokeWidth="1.5" strokeLinecap="round"/>
        <path d="M18 29L30 29" stroke="var(--logo-stroke-color)" strokeWidth="1.5" strokeLinecap="round"/>
        <path d="M18 23L24 20L30 23" stroke="var(--logo-stroke-color)" strokeWidth="1.5" strokeLinecap="round"/>
        <path d="M18 29L24 32L30 29" stroke="var(--logo-stroke-color)" strokeWidth="1.5" strokeLinecap="round"/>
        <circle cx="24" cy="26" r="4" fill="var(--primary-glow-color)" className="logo-core-glow"/>
        <circle cx="24" cy="26" r="2" fill="var(--logo-fill-color)"/>
    </svg>
);


const ThemeSwitcher = ({ theme, toggleTheme }: { theme: string, toggleTheme: () => void }) => (
    <div className="theme-switch-wrapper">
        <label className="theme-switch" htmlFor="checkbox">
            <input type="checkbox" id="checkbox" onChange={toggleTheme} checked={theme === 'dark'} />
            <div className="slider round">
                <span className="sun-icon">☀️</span>
                <span className="moon-icon">🌙</span>
            </div>
        </label>
    </div>
);

const Header = ({ theme, toggleTheme }: { theme: string, toggleTheme: () => void }) => (
    <header>
        <div className="header-left">
            <Logo />
            <div className="header-text-container">
                <h1>AI Network Security</h1>
                <p>Real-time Threat Monitoring</p>
            </div>
        </div>
        <ThemeSwitcher theme={theme} toggleTheme={toggleTheme} />
    </header>
);

const TrafficChart = () => {
    const NUM_POINTS = 41;
    const VIEWBOX_WIDTH = 200;
    const VIEWBOX_HEIGHT = 100;
    const MAX_Y = 80;
    const MIN_Y = 20;

    const generateInitialData = () => {
      return Array.from({ length: NUM_POINTS }, () => 
        Math.floor(Math.random() * (MAX_Y - MIN_Y + 1)) + MIN_Y
      );
    };
  
    const [dataPoints, setDataPoints] = useState(generateInitialData);
  
    useEffect(() => {
      const interval = setInterval(() => {
        setDataPoints(currentPoints => {
          const newPoint = Math.floor(Math.random() * (MAX_Y - MIN_Y + 1)) + MIN_Y;
          return [...currentPoints.slice(1), newPoint];
        });
      }, 500); 
  
      return () => clearInterval(interval);
    }, []);
  
    const pointsString = useMemo(() => 
      dataPoints.map((point, index) => 
        `${(index * VIEWBOX_WIDTH) / (NUM_POINTS - 1)},${point}`
      ).join(' '),
      [dataPoints]
    );

    const areaPath = `M0,${VIEWBOX_HEIGHT} L${pointsString} L${VIEWBOX_WIDTH},${VIEWBOX_HEIGHT} Z`;
  
    return (
      <div className="traffic-chart">
          <div className="chart-container">
              <h3>Live Traffic</h3>
              <svg viewBox={`0 0 ${VIEWBOX_WIDTH} ${VIEWBOX_HEIGHT}`} preserveAspectRatio="xMidYMid meet">
                  <defs>
                      <linearGradient id="trafficGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="var(--primary-color)" stopOpacity="0.4"/>
                          <stop offset="100%" stopColor="var(--primary-color)" stopOpacity="0"/>
                      </linearGradient>
                  </defs>
                  <g className="chart-grid">
                    <line x1="0" y1="25" x2="200" y2="25" className="chart-grid-line" />
                    <line x1="0" y1="50" x2="200" y2="50" className="chart-grid-line" />
                    <line x1="0" y1="75" x2="200" y2="75" className="chart-grid-line" />
                  </g>
                  <path d={areaPath} fill="url(#trafficGradient)" />
                  <polyline
                      className="traffic-line"
                      fill="none"
                      stroke="var(--primary-color)"
                      strokeWidth="2"
                      points={pointsString}
                  />
              </svg>
          </div>
      </div>
    );
};

// --- Network Visualizer Components ---
type NodeData = { id: string; cx: number; cy: number; label: string; ip: string; type: 'server' | 'normal' };
type EdgeData = { from: string; to: string };
type NodeDetailsData = NodeData & { threat?: ThreatDetails };
type ConnectionDetail = { from: NodeData, to: NodeData };


const NODES: NodeData[] = [
    { id: 'server', cx: 50, cy: 50, label: 'Main Server', ip: '10.0.0.1', type: 'server' },
    { id: 'node-a', cx: 100, cy: 25, label: 'Firewall', ip: FAKE_IPS[0], type: 'normal' },
    { id: 'node-b', cx: 100, cy: 75, label: 'Workstation A', ip: FAKE_IPS[1], type: 'normal' },
    { id: 'node-c', cx: 150, cy: 50, label: 'Database', ip: FAKE_IPS[2], type: 'normal' },
    { id: 'external-a', cx: 150, cy: 15, label: 'Ext. Gateway', ip: FAKE_IPS[3], type: 'normal' },
];

const EDGES: EdgeData[] = [
    { from: 'server', to: 'node-a' },
    { from: 'server', to: 'node-b' },
    { from: 'node-a', to: 'node-c' },
    { from: 'node-b', to: 'node-c' },
    { from: 'node-a', to: 'external-a'},
];


// FIX: Define props as a type and use React.FC to correctly type the component for use with special props like 'key'.
type NodeProps = { cx: number, cy: number, type: string, label: string, onClick: (e: React.MouseEvent) => void, isSelected: boolean, onMouseEnter: () => void, onMouseLeave: () => void, showLabel: boolean };
const Node: React.FC<NodeProps> = ({ cx, cy, type, label, onClick, isSelected, onMouseEnter, onMouseLeave, showLabel }) => (
    <g onClick={onClick} onMouseEnter={onMouseEnter} onMouseLeave={onMouseLeave} className={`network-node network-node-${type} ${isSelected ? 'selected' : ''}`} role="button" tabIndex={0}>
        <g>
            <circle className="node-glow" cx={cx} cy={cy} r="2" />
            <circle className="node-body" cx={cx} cy={cy} r="2" />
        </g>
        {showLabel && <text x={cx} y={cy + 5} className="node-label">{label}</text>}
    </g>
);

// FIX: Define props as a type and use React.FC to correctly type the component for use with special props like 'key'.
type EdgeProps = { x1: number, y1: number, x2: number, y2: number, isThreat: boolean, isSelected: boolean, isHovered: boolean };
const Edge: React.FC<EdgeProps> = ({ x1, y1, x2, y2, isThreat, isSelected, isHovered }) => (
    <line x1={x1} y1={y1} x2={x2} y2={y2} className={`network-edge ${isThreat ? 'network-edge-threat' : ''} ${isSelected ? 'network-edge-selected' : ''} ${isHovered ? 'network-edge-hovered' : ''}`}></line>
);

const NodeDetailsPanel = ({ details, connections }: { details: NodeDetailsData, connections: ConnectionDetail[] }) => (
    <foreignObject x={details.cx + 4} y={details.cy - 40} width="95" height="120">
        <div xmlns="http://www.w3.org/1999/xhtml" className="node-details-panel">
            <h4>{details.label}</h4>
            <p><strong>IP:</strong> {details.ip}</p>
            <p><strong>Type:</strong> {details.type.charAt(0).toUpperCase() + details.type.slice(1)}</p>
            {details.threat ? (
                <div className="threat-info">
                    <strong>Threat Detected!</strong>
                    <p>{details.threat.threatType}</p>
                    <p className={details.threat.severity === 'Critical' ? 'severity-critical' : 'severity-high'}>{details.threat.severity} Severity</p>
                </div>
            ) : (
                <p><strong>Status:</strong> <span className="status-secure-inline">Secure</span></p>
            )}
             {connections.length > 0 && (
                <div className="connections-section">
                    <strong>Connections:</strong>
                    <ul className="connections-list">
                        {connections.map((conn, index) => (
                            <li key={index}>
                               {conn.from.ip} &rarr; {conn.to.ip}
                            </li>
                        ))}
                    </ul>
                </div>
            )}
        </div>
    </foreignObject>
);

const NetworkVisualizer = ({ threats }: { threats: ThreatDetails[] }) => {
    const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
    const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

    const threatSourceIps = useMemo(() => new Set(threats.map(t => t.sourceIp)), [threats]);

    const handleNodeClick = (nodeId: string, e: React.MouseEvent) => {
        e.stopPropagation();
        setSelectedNodeId(currentId => currentId === nodeId ? null : nodeId);
    };
    
    const handleNodeMouseEnter = (nodeId: string) => setHoveredNodeId(nodeId);
    const handleNodeMouseLeave = () => setHoveredNodeId(null);

    const handleBgClick = () => {
        setSelectedNodeId(null);
    };

    const nodeMap = useMemo(() => new Map(NODES.map(node => [node.id, node])), []);
    
    const selectedEdges = useMemo(() => {
        if (!selectedNodeId) return new Set<string>();
        const edges = new Set<string>();
        EDGES.forEach((edge, i) => {
            if (edge.from === selectedNodeId || edge.to === selectedNodeId) {
                const edgeKey = `${edge.from}-${edge.to}-${i}`;
                edges.add(edgeKey);
            }
        });
        return edges;
    }, [selectedNodeId]);

    const selectedNodeDetails: NodeDetailsData | null = useMemo(() => {
        if (!selectedNodeId) return null;
        const node = nodeMap.get(selectedNodeId);
        if (!node) return null;
        const threat = threats.find(t => t.sourceIp === node.ip);
        return { ...node, threat };
    }, [selectedNodeId, threats, nodeMap]);

    const selectedNodeConnections: ConnectionDetail[] = useMemo(() => {
        if (!selectedNodeId) return [];
        const connectedEdges = EDGES.filter(edge => edge.from === selectedNodeId || edge.to === selectedNodeId);
        return connectedEdges
            .map(edge => {
                const fromNode = nodeMap.get(edge.from);
                const toNode = nodeMap.get(edge.to);
                return { from: fromNode, to: toNode };
            })
            .filter((conn): conn is ConnectionDetail => !!conn.from && !!conn.to);
    }, [selectedNodeId, nodeMap]);

    const viewTransform = useMemo(() => {
        const ZOOM_SCALE = 1.5;
        const VIEWBOX_CENTER_X = 100;
        const VIEWBOX_CENTER_Y = 50;

        if (!selectedNodeId) {
            return 'translate(0, 0) scale(1)';
        }
        
        const node = nodeMap.get(selectedNodeId);
        if (!node) {
            return 'translate(0, 0) scale(1)'; // Fallback
        }

        const tx = VIEWBOX_CENTER_X - ZOOM_SCALE * node.cx;
        const ty = VIEWBOX_CENTER_Y - ZOOM_SCALE * node.cy;

        return `translate(${tx}, ${ty}) scale(${ZOOM_SCALE})`;
    }, [selectedNodeId, nodeMap]);


    return (
        <div className="network-visualizer">
            <div className="visualizer-container">
                <h3>Network Topology</h3>
                <div className="visualizer-content">
                    <svg viewBox="0 0 200 100" preserveAspectRatio="xMidYMid meet" onClick={handleBgClick}>
                        <defs>
                            <pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse">
                                <path d="M 10 0 L 0 0 0 10" fill="none" className="network-grid-pattern" />
                            </pattern>
                        </defs>
                        <rect width="200" height="100" fill="url(#grid)" className="network-grid-bg" />
                        
                        <g className="network-canvas" transform={viewTransform}>
                            {EDGES.map((edge, i) => {
                                const fromNode = nodeMap.get(edge.from);
                                const toNode = nodeMap.get(edge.to);
                                if (!fromNode || !toNode) return null;
                                
                                const isThreat = threatSourceIps.has(fromNode.ip) || threatSourceIps.has(toNode.ip);
                                const edgeKey = `${edge.from}-${edge.to}-${i}`;
                                const isSelected = selectedEdges.has(edgeKey);
                                const isHovered = hoveredNodeId !== null && (edge.from === hoveredNodeId || edge.to === hoveredNodeId);

                                return <Edge key={i} x1={fromNode.cx} y1={fromNode.cy} x2={toNode.cx} y2={toNode.cy} isThreat={isThreat} isSelected={isSelected} isHovered={isHovered}/>;
                            })}

                            {NODES.map(node => {
                               const isThreatSource = threatSourceIps.has(node.ip);
                               const nodeIsHovered = hoveredNodeId === node.id;
                               return (
                                 <Node
                                     key={node.id}
                                     cx={node.cx}
                                     cy={node.cy}
                                     type={isThreatSource ? 'threat' : node.type}
                                     label={node.label}
                                     isSelected={selectedNodeId === node.id}
                                     onClick={(e) => handleNodeClick(node.id, e)}
                                     onMouseEnter={() => handleNodeMouseEnter(node.id)}
                                     onMouseLeave={handleNodeMouseLeave}
                                     showLabel={true}
                                 />
                               );
                            })}

                            {selectedNodeDetails && <NodeDetailsPanel details={selectedNodeDetails} connections={selectedNodeConnections} />}
                        </g>
                    </svg>
                </div>
            </div>
        </div>
    );
};

const COUNTRY_COORDINATES: { [key: string]: [number, number] } = {
    'North Korea': [835, 204],
    'Russia': [700, 150],
    'China': [780, 230],
    'USA': [240, 200],
    'Brazil': [380, 380],
    'Germany': [545, 170],
};

const WorldMap = ({ origin }: { origin: string }) => {
    const coords = COUNTRY_COORDINATES[origin];

    return (
        <div className="threat-origin-map">
            <svg viewBox="0 0 1000 500" className="world-map-svg" preserveAspectRatio="xMidYMid slice">
                <path d="M1000 250.2V218.8c-12.2-2-23.3-3.1-33.4-3.1-9.6 0-19.6 0.8-29.8 2.2-20.1 2.9-40.2 6-56.5 6-10.1 0-20.4-1.2-30.2-3.4-18.7-4.1-39.2-6.5-57.8-6.5-16.1 0-33.3 2-49.3 5.5-13.8 3-28.2 4.9-42.2 4.9-10.4 0-21.2-1.1-31.5-3.1-12.7-2.5-27.3-3.9-42.2-3.9-12.8 0-25.9 1.1-38.3 3.1-13.8 2.3-28.5 3.6-42.5 3.6-11.8 0-24-1-35.8-3-11.6-1.9-23.7-2.9-35.8-2.9-15.1 0-29.9 1.6-43.1 4.7-10.2 2.4-20.2 3.8-28.8 3.8-10.9 0-20.8-1.5-29.4-4.5-8.1-2.8-15.5-4.5-22.3-4.5-10.4 0-20.1 2.2-28.3 6.3-5.2 2.6-10.1 4.5-14.7 4.5-11.3 0-22.3-3.1-32-8.5-10.9-6-19.1-14.5-27.3-24.8-11.3-14.3-21.9-28.2-30.8-39.2-7.8-9.7-14.4-17.6-19.1-23.2-12-14.3-22.3-25.1-31.8-32.3-8.8-6.7-17.1-10.9-24.5-12.7-5.5-1.4-11.1-2.1-16.5-2.1-7.1 0-14.1 1.2-20.3 3.4-11.2 4-20.4 9.9-27.1 17-5.4 5.9-9.5 12.3-12.3 18.8-5.2 12.3-7.5 25.1-7.5 37.3v34.9h-10.1c-9.6 0-18.6 2.3-26.7 6.6-8.7 4.6-16.2 10.9-22.1 18.6-6.4 8.2-11.4 17.8-14.7 28.3-2.1 6.8-3.4 14-3.4 21.4 0 9.7 2 19.8 5.7 29.8 4.3 11.5 10.4 22.3 17.8 31.8 3.5 4.5 7.1 8.8 10.6 12.9 8.2 9.5 16.9 17.6 25.2 24.1 11.4 8.7 23.3 15.6 34.6 20.3 15.1 6.2 30.6 10.1 45 10.1 11.8 0 24-2 36-5.7 13.9-4.3 28.5-10 42.5-16.1 14.6-6.4 28.9-13.4 41.5-20.4 12.4-6.9 23.2-13.6 32-19.4 15.3-10.1 28.3-18.4 38.3-24.3 12.9-7.7 24.3-13.4 33.6-16.9 13.6-5.1 25.7-8 35.8-8 10.1 0 20.2 1.9 29.6 5.5 17.1 6.6 36.2 10.2 52.8 10.2 12.3 0 25.7-1.8 39.4-5.2 14.2-3.6 29.3-5.4 43.8-5.4 10.9 0 22.3 1.2 33.6 3.6 15.1 3.4 31.5 5.1 47 5.1 12.6 0 25.8-1.5 38.6-4.5 10.6-2.5 21.4-4.2 31.8-4.2 14.2 0 29.1 2.3 43.1 6.6 12.2 3.8 25.4 5.9 38.6 5.9 18.2 0 38.3-3.6 57.6-10.6 11.4-4.1 23-8.8 34.1-13.8 12.7-5.8 25.2-11.7 36.9-17.3 11.6-5.5 22.1-10.7 31-15.1 13.4-6.6 25-12.3 34.6-16.4 11.2-4.8 21.5-8.5 30.4-10.9 11.2-3.1 21.7-4.9 31-4.9 8.8 0 17.8 1.1 26.5 3.1 11.4 2.7 23.3 4.4 35.1 4.4h3.6c4.6 0 9.2-0.2 13.8-0.5 4.6-0.3 9.2-0.8 13.8-1.4 4.3-0.5 8.6-1.1 12.9-1.8 8.1-1.4 16.4-3 24.5-4.7 12.9-2.8 26-5.7 38.6-8.2zM21.4 243.6c-4.3 11.5-10.4 22.3-17.8 31.8-3.5 4.5-7.1 8.8-10.6 12.9-8.2 9.5-16.9 17.6-25.2 24.1-11.4 8.7-23.3 15.6-34.6 20.3-15.1 6.2-30.6 10.1-45 10.1-11.8 0-24-2-36-5.7-13.9-4.3-28.5-10-42.5-16.1-14.6-6.4-28.9-13.4-41.5-20.4-12.4-6.9-23.2-13.6-32-19.4-15.3-10.1-28.3-18.4-38.3-24.3-12.9-7.7-24.3-13.4-33.6-16.9-13.6-5.1-25.7-8-35.8-8-10.1 0-20.2 1.9-29.6 5.5-17.1 6.6-36.2 10.2-52.8 10.2-12.3 0-25.7-1.8-39.4-5.2-14.2-3.6-29.3-5.4-43.8-5.4-10.9 0-22.3 1.2-33.6 3.6-15.1 3.4-31.5 5.1-47 5.1-12.6 0-25.8-1.5-38.6-4.5-10.6-2.5-21.4-4.2-31.8-4.2-14.2 0-29.1 2.3-43.1 6.6-12.2 3.8-25.4 5.9-38.6 5.9-18.2 0-38.3-3.6-57.6-10.6-11.4-4.1-23-8.8-34.1-13.8-12.7-5.8-25.2-11.7-36.9-17.3-11.6-5.5-22.1-10.7-31-15.1-13.4-6.6-25-12.3-34.6-16.4-11.2-4.8-21.5-8.5-30.4-10.9-11.2-3.1-21.7-4.9-31-4.9-8.8 0-17.8 1.1-26.5 3.1-11.4 2.7-23.3 4.4-35.1 4.4h-3.6c-4.6 0-9.2-0.2-13.8-0.5-4.6-0.3-9.2-0.8-13.8-1.4-4.3-0.5-8.6-1.1-12.9-1.8-8.1-1.4-16.4-3-24.5-4.7-12.9-2.8-26-5.7-38.6-8.2-12.2-2-23.3-3.1-33.4-3.1-9.6 0-19.6 0.8-29.8 2.2-20.1 2.9-40.2 6-56.5 6-10.1 0-20.4-1.2-30.2-3.4-18.7-4.1-39.2-6.5-57.8-6.5-16.1 0-33.3 2-49.3 5.5-13.8 3-28.2 4.9-42.2 4.9-10.4 0-21.2-1.1-31.5-3.1-12.7-2.5-27.3-3.9-42.2-3.9-12.8 0-25.9 1.1-38.3 3.1-13.8 2.3-28.5 3.6-42.5 3.6-11.8 0-24-1-35.8-3-11.6-1.9-23.7-2.9-35.8-2.9-15.1 0-29.9 1.6-43.1 4.7-10.2 2.4-20.2 3.8-28.8 3.8-10.9 0-20.8-1.5-29.4-4.5-8.1-2.8-15.5-4.5-22.3-4.5-10.4 0-20.1 2.2-28.3 6.3-5.2 2.6-10.1 4.5-14.7 4.5-11.3 0-22.3-3.1-32-8.5-10.9-6-19.1-14.5-27.3-24.8-11.3-14.3-21.9-28.2-30.8-39.2-7.8-9.7-14.4-17.6-19.1-23.2-12-14.3-22.3-25.1-31.8-32.3-8.8-6.7-17.1-10.9-24.5-12.7-5.5-1.4-11.1-2.1-16.5-2.1-7.1 0-14.1 1.2-20.3 3.4-11.2 4-20.4 9.9-27.1 17-5.4 5.9-9.5 12.3-12.3 18.8-5.2 12.3-7.5 25.1-7.5 37.3v-34.9h10.1c9.6 0 18.6-2.3 26.7-6.6 8.7-4.6 16.2-10.9 22.1-18.6 6.4-8.2 11.4-17.8 14.7-28.3 2.1-6.8 3.4-14 3.4-21.4 0-9.7-2-19.8-5.7-29.8z"/>
                {coords && (
                    <g className="map-marker">
                        <circle cx={coords[0]} cy={coords[1]} r="15" className="map-marker-pulse" />
                        <circle cx={coords[0]} cy={coords[1]} r="8" className="map-marker-dot" />
                    </g>
                )}
            </svg>
        </div>
    );
};

const LogDetails = ({ details, onRemediate }: { details: ThreatDetails, onRemediate: (threatId: string, action: string) => void }) => {
    const [isRemediating, setIsRemediating] = useState(false);
    const [remediationStep, setRemediationStep] = useState(details.remediationAction);

    const getRemediationStep = async () => {
      try {
        const response = await ai.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: `Given the threat type "${details.threatType}" from IP "${details.sourceIp}", suggest a one-sentence, user-friendly remediation action.`,
        });
        setRemediationStep(response.text.trim());
      } catch (error) {
        console.error("Error fetching remediation step:", error);
        setRemediationStep(details.remediationAction); // Fallback
      }
    };

    useEffect(() => {
        if (details.isRemediable && !details.remediationAction) {
            getRemediationStep();
        }
    }, [details]);

    const handleRemediate = async () => {
        if (!remediationStep) return;
        setIsRemediating(true);
        // Simulate remediation delay
        await new Promise(resolve => setTimeout(resolve, 2000));
        onRemediate(details.id, remediationStep);
        setIsRemediating(false);
    };

    return (
        <div className="log-details-expanded">
            <h3>Threat Details: {details.threatType}</h3>
            <div className="detail-item">
                <strong>Source IP:</strong> {details.sourceIp}
            </div>
            <div className="detail-item">
                <strong>Severity:</strong> <span className={details.severity === 'Critical' ? 'severity-critical' : 'severity-high'}>{details.severity}</span>
            </div>
            <div className="detail-item detail-item-origin">
                 <div>
                    <strong>Suspected Origin:</strong>
                    <span>{details.origin}</span>
                </div>
                <WorldMap origin={details.origin} />
            </div>
             <div className="detail-item">
                <strong>Initial Recommendation:</strong> {details.recommendation}
            </div>
            {details.remediated ? (
                <div className="remediation-success">✓ Threat Remediated</div>
            ) : details.isRemediable && (
                <div className="remediation-section">
                    <h4>Automated Remediation</h4>
                    <p>{remediationStep || 'Generating suggestion...'}</p>
                    <button className="remediation-button" onClick={handleRemediate} disabled={isRemediating || !remediationStep}>
                       {isRemediating ? 'Applying...' : 'Apply Fix'}
                    </button>
                </div>
            )}
        </div>
    );
};


const NetworkLog = ({ logs, threats, onRemediate }: { logs: LogEntry[], threats: ThreatDetails[], onRemediate: (threatId: string, action: string) => void }) => {
    const [expandedLogId, setExpandedLogId] = useState<string | null>(null);
    const logContainerRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (logContainerRef.current) {
            logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
        }
    }, [logs]);

    const handleLogClick = (log: LogEntry) => {
      if (log.details) {
        setExpandedLogId(expandedLogId === log.id ? null : log.id);
      }
    };

    return (
        <div className="network-log">
            <div className="section-header">
                <h2>Network Log</h2>
                <button className="export-button">Export Logs</button>
            </div>
            <div className="log-entries" ref={logContainerRef}>
                {logs.map(log => {
                    const isThreat = log.type === 'ERROR' && log.details;
                    const logTypeClass = log.type.toLowerCase();
                    const logSeverityClass = isThreat ? (log.details.severity === 'Critical' ? 'severity-log-critical' : 'severity-log-high') : '';
                    
                    return (
                        <React.Fragment key={log.id}>
                          <div
                              className={`log-entry ${logTypeClass} ${logSeverityClass} ${isThreat ? 'clickable' : ''}`}
                              onClick={() => handleLogClick(log)}
                              role={isThreat ? "button" : "listitem"}
                              tabIndex={isThreat ? 0 : -1}
                          >
                              <span className="log-timestamp">{log.timestamp}</span>
                              <span className="log-ip">{log.sourceIp}</span>
                              <span className="log-message">{log.message}</span>
                          </div>
                           {isThreat && expandedLogId === log.id && (
                             <LogDetails details={log.details} onRemediate={onRemediate}/>
                           )}
                        </React.Fragment>
                    );
                })}
            </div>
        </div>
    );
};

const ThreatDetection = ({ status, onScan, onResolve, onBlockIp, threatCount, activeThreats, unauthorizedAttempts }: { status: Status, onScan: () => void, onResolve: () => void, onBlockIp: (ip: string) => void, threatCount: number, activeThreats: ThreatDetails[], unauthorizedAttempts: LogEntry[] }) => {
    const [summary, setSummary] = useState('');
    const [isSummarizing, setIsSummarizing] = useState(false);
    const [manualIp, setManualIp] = useState('');
    const [flashAlert, setFlashAlert] = useState(false);
    const prevAttemptCount = useRef(unauthorizedAttempts.length);

    const statusClasses = {
        'Secure': 'status-secure',
        'Scanning': 'status-scanning',
        'Threat Found': 'status-threat',
    };

    useEffect(() => {
        if (activeThreats.length > 0) {
            const generateSummary = async () => {
                setIsSummarizing(true);
                setSummary('');
                try {
                    const threatDescriptions = activeThreats.map(t => `- Type: ${t.threatType}, Source: ${t.sourceIp}, Severity: ${t.severity}`).join('\n');
                    const prompt = `Concisely summarize the following active network security threats in one sentence, focusing on the most critical patterns or types. Threats:\n${threatDescriptions}`;

                    const response = await ai.models.generateContent({
                        model: 'gemini-2.5-flash',
                        contents: prompt,
                    });
                    setSummary(response.text.trim());
                } catch (error) {
                    console.error("Error generating threat summary:", error);
                    setSummary("Could not generate threat summary.");
                } finally {
                    setIsSummarizing(false);
                }
            };
            generateSummary();
        } else {
            setSummary('');
        }
    }, [activeThreats]);

    useEffect(() => {
        if (unauthorizedAttempts.length > prevAttemptCount.current) {
            setFlashAlert(true);
            const timer = setTimeout(() => {
                setFlashAlert(false);
            }, 1500); // Match CSS animation duration
            
            return () => clearTimeout(timer);
        }
        prevAttemptCount.current = unauthorizedAttempts.length;
    }, [unauthorizedAttempts]);


    const handleManualBlock = () => {
        if (manualIp.trim()) {
            onBlockIp(manualIp.trim());
            setManualIp('');
        }
    };


    return (
        <div className={`threat-detection ${status === 'Threat Found' ? 'threat-alert' : ''}`}>
            <h2>Threat Detection</h2>
            <p>Proactive monitoring of network traffic for malicious activity.</p>
            <div className="status-indicator">
                <span>Status:</span>
                <span className={statusClasses[status]}>{status}</span>
            </div>
            {status === 'Threat Found' && (
                <>
                    <div className="alert-message">{threatCount} active threat(s) detected!</div>
                    <div className="threat-summary">
                        {isSummarizing && <p>Generating summary...</p>}
                        {summary && <p>{summary}</p>}
                    </div>
                </>
            )}
            {unauthorizedAttempts.length > 0 && (
                <div className={`unauthorized-access-alert ${flashAlert ? 'new-alert-flash' : ''}`}>
                    <h4>Unauthorized Device Alerts</h4>
                    <p>{unauthorizedAttempts.length} new device(s) attempted to connect:</p>
                    <ul className="unauthorized-ip-list">
                        {unauthorizedAttempts.map((attempt, index) => (
                            <li key={index}>
                                <span className="ip-address">{attempt.sourceIp}</span>
                                <span className="timestamp">{attempt.timestamp}</span>
                            </li>
                        ))}
                    </ul>
                </div>
            )}
            <div className="manual-block-section">
                <h4>Manual Intervention</h4>
                <div className="manual-block-input-group">
                    <input
                        type="text"
                        value={manualIp}
                        onChange={(e) => setManualIp(e.target.value)}
                        placeholder="Enter IP to block..."
                        aria-label="IP address to block"
                    />
                    <button onClick={handleManualBlock} disabled={!manualIp.trim()}>
                        Block IP
                    </button>
                </div>
            </div>
            <div className="action-buttons">
                <button onClick={onScan} disabled={status === 'Scanning'}>
                    {status === 'Scanning' ? 'Scanning...' : 'Start Scan'}
                </button>
                {status === 'Threat Found' && (
                    <button className="resolve-button" onClick={onResolve}>Resolve All</button>
                )}
            </div>
        </div>
    );
};

const Dashboard = ({ threats }: { threats: ThreatDetails[] }) => (
    <div className="dashboard-grid">
        <TrafficChart />
        <NetworkVisualizer threats={threats} />
    </div>
);

const App = () => {
    const [status, setStatus] = useState<Status>('Secure');
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [threats, setThreats] = useState<ThreatDetails[]>([]);
    const [unauthorizedAttempts, setUnauthorizedAttempts] = useState<LogEntry[]>([]);
    const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark');
    const scanIntervalRef = useRef<number | null>(null);

    useEffect(() => {
        document.body.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
    }, [theme]);

    const toggleTheme = () => {
        setTheme(prevTheme => (prevTheme === 'light' ? 'dark' : 'light'));
    };
    
    const addLogEntry = (entry: LogEntry) => {
        setLogs(prevLogs => [...prevLogs.slice(-100), entry]);
        if (entry.details) {
            setThreats(prevThreats => [...prevThreats, entry.details!]);
            setStatus('Threat Found');
        }
        if (entry.type === 'WARNING' && entry.message.includes('Unauthorized access')) {
            setUnauthorizedAttempts(prev => [...prev.slice(-10), entry].sort((a, b) => b.id.localeCompare(a.id)));
        }
    };
    
    useEffect(() => {
        const interval = setInterval(() => {
            if (status !== 'Scanning') {
                addLogEntry(generateRandomLog(false));
            }
        }, 3000);
        return () => clearInterval(interval);
    }, [status]);


    const startScan = () => {
        setStatus('Scanning');
        if (scanIntervalRef.current) clearInterval(scanIntervalRef.current);

        const scanDuration = 10000; // 10 seconds
        const scanEndTime = Date.now() + scanDuration;

        scanIntervalRef.current = window.setInterval(() => {
            if (Date.now() > scanEndTime) {
                stopScan();
                return;
            }
            addLogEntry(generateRandomLog(true));
        }, 500);
    };

    const stopScan = () => {
        if (scanIntervalRef.current) clearInterval(scanIntervalRef.current);
        scanIntervalRef.current = null;
        if (threats.every(t => t.remediated)) {
             setStatus('Secure');
        } else {
             setStatus('Threat Found');
        }
    };

    const handleResolve = () => {
        setThreats(prev => prev.map(t => ({ ...t, remediated: true })));
        setLogs(prev => prev.map(log => {
            if (log.details) {
                return { ...log, details: { ...log.details, remediated: true } };
            }
            return log;
        }));
        setStatus('Secure');
        addLogEntry({
          id: `log-${Date.now()}`,
          timestamp: new Date().toLocaleTimeString(),
          type: 'INFO',
          message: 'All threats marked as resolved by user.',
          sourceIp: '127.0.0.1'
        });
    };

    const handleRemediate = (threatId: string, action: string) => {
        setThreats(prev => prev.map(t => t.id === threatId ? { ...t, remediated: true } : t));
        setLogs(prev => prev.map(log => {
            if (log.details?.id === threatId) {
                return { ...log, details: { ...log.details, remediated: true } };
            }
            return log;
        }));

        addLogEntry({
          id: `log-${Date.now()}`,
          timestamp: new Date().toLocaleTimeString(),
          type: 'INFO',
          message: `Remediation applied for threat ${threatId}: ${action}`,
          sourceIp: '127.0.0.1'
        });

        // Check if all threats are now remediated
        const allRemediated = threats.every(t => t.id === threatId || t.remediated);
        if (allRemediated && status === 'Threat Found') {
            setStatus('Secure');
        }
    };
    
    const handleBlockIp = (ip: string) => {
      addLogEntry({
        id: `log-${Date.now()}`,
        timestamp: new Date().toLocaleTimeString(),
        type: 'WARNING',
        message: `Manual block initiated for IP: ${ip}`,
        sourceIp: ip
      });
    };

    const activeThreats = useMemo(() => threats.filter(t => !t.remediated), [threats]);

    return (
        <>
            <Header theme={theme} toggleTheme={toggleTheme} />
            <main>
                <div className="main-grid">
                    <ThreatDetection
                        status={status}
                        onScan={startScan}
                        onResolve={handleResolve}
                        onBlockIp={handleBlockIp}
                        threatCount={activeThreats.length}
                        activeThreats={activeThreats}
                        unauthorizedAttempts={unauthorizedAttempts}
                    />
                    <Dashboard threats={activeThreats} />
                    <NetworkLog logs={logs} threats={threats} onRemediate={handleRemediate}/>
                </div>
            </main>
        </>
    );
};

const root = ReactDOM.createRoot(document.getElementById('root') as HTMLElement);
root.render(<App />);