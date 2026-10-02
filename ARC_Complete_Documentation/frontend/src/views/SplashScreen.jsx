import React, { useState, useEffect, useRef } from 'react';

const SplashScreen = ({ onComplete }) => {
  const [currentPct, setCurrentPct] = useState(12);
  const [logs, setLogs] = useState([]);
  const terminalRef = useRef(null);

  const dynamicLogs = [
    { tag: '[OK]', color: 'text-tertiary', text: 'Initializing Tauri Rust IPC bus (socket: /run/arc/ipc.sock)...', latency: '0.4ms' },
    { tag: '[OK]', color: 'text-tertiary', text: 'Connecting to Redpanda / Kafka cluster (3 partitions)...', latency: 'SYNCED' },
    { tag: '[OK]', color: 'text-tertiary', text: 'Loading Redis FSM sequence memory state (18 keys active)...', latency: '1.2ms' },
    { tag: '[OK]', color: 'text-primary', text: 'Compiling Sigma AST detection rules engine (142 rules loaded)...', latency: '34.8ms' },
    { tag: '[SCAN]', color: 'text-tertiary', text: 'eBPF probe attachment to syscall sys_enter_execve confirmed.', latency: '2.1ms' },
    { tag: '[OK]', color: 'text-tertiary', text: 'Telemetry stream established to Core SIEM node (TLS 1.3 cipher: AES_256_GCM).', latency: '14.0ms' },
    { tag: '[OK]', color: 'text-primary', text: 'Security Analyst environment state primed. Awaiting workspace dispatch...', latency: '0.9ms' }
  ];

  useEffect(() => {
    let pct = 12;
    let logIndex = 0;

    const interval = setInterval(() => {
      if (pct < 99) {
        pct += Math.floor(Math.random() * 4) + 1;
        if (pct > 99) pct = 99;
        setCurrentPct(pct);
      }

      if (logIndex < dynamicLogs.length && pct > 20 + (logIndex * 10)) {
        setLogs(prev => [...prev, dynamicLogs[logIndex]]);
        logIndex++;
      }

      if (pct >= 99 && logIndex >= dynamicLogs.length) {
        clearInterval(interval);
        setTimeout(() => {
          if (onComplete) onComplete();
        }, 1500);
      }
    }, 450);

    return () => clearInterval(interval);
  }, [onComplete]);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  const handleDiagnostic = () => {
    setLogs(prev => [
      ...prev,
      { tag: '[DIAGNOSTIC]', color: 'text-error', text: 'Manual diagnostic trace requested by SOC analyst console interrupt.', latency: '---' }
    ]);
  };

  const handleReset = () => {
    setCurrentPct(12);
    setLogs([]);
  };

  return (
    <div className="bg-surface-container-lowest text-on-surface font-body-md text-body-md antialiased min-h-screen w-full flex items-center justify-center p-space-lg">
      <div className="flex flex-col w-full">
        <div className="relative w-full max-w-5xl mx-auto flex flex-col items-center justify-between p-space-md sm:p-space-lg text-on-surface">
          {/* Ambient Backdrop Halo & Subtle Grid */}
          <div className="absolute -top-24 left-1/2 -translate-x-1/2 w-[580px] h-[580px] bg-primary/5 rounded-full blur-3xl pointer-events-none -z-10"></div>
          <div className="absolute -bottom-20 right-10 w-96 h-96 bg-tertiary/5 rounded-full blur-2xl pointer-events-none -z-10"></div>
          
          {/* Top Status Header Strip */}
          <header className="w-full flex items-center justify-between px-space-md py-space-sm bg-surface-container-low rounded-lg shadow-sm mb-space-lg">
            <div className="flex items-center gap-space-sm">
              <span className="w-2 h-2 rounded-full bg-tertiary animate-pulse"></span>
              <span className="font-label-sm text-label-sm text-on-surface-variant tracking-wider uppercase">SECURE BOOT ENVIRONMENT</span>
              <span className="text-outline-variant font-label-sm text-label-sm">|</span>
              <span className="font-label-sm text-label-sm text-primary">SESSION #8841-B9</span>
            </div>
            <div className="flex items-center gap-space-md text-on-surface-variant">
              <span className="font-label-sm text-label-sm hidden sm:inline">HOST: <span className="text-on-surface font-semibold">SOC-STATION-04.NET.CORP</span></span>
              <span className="font-label-sm text-label-sm px-space-xs py-0.5 rounded bg-surface-container text-tertiary">FIPS-140-3</span>
            </div>
          </header>

          {/* Main Hero Unit: Logo, Radar & Branding */}
          <div className="w-full flex flex-col items-center text-center my-space-md relative">
            <div className="relative w-44 h-44 flex items-center justify-center mb-space-md">
              <div className="absolute inset-0 rounded-full bg-surface-container-lowest/80 shadow-inner"></div>
              <div className="absolute inset-3 rounded-full bg-surface-container-low/40"></div>
              <div className="absolute inset-8 rounded-full bg-surface-container/60"></div>
              
              <svg className="absolute inset-0 w-full h-full animate-[spin_4s_linear_infinite] pointer-events-none opacity-40 text-primary" viewBox="0 0 160 160">
                <defs>
                  <linearGradient id="radarSweep" x1="0%" x2="100%" y1="0%" y2="100%">
                    <stop offset="0%" stopColor="currentColor" stopOpacity="0.8"></stop>
                    <stop offset="60%" stopColor="currentColor" stopOpacity="0.1"></stop>
                    <stop offset="100%" stopColor="currentColor" stopOpacity="0"></stop>
                  </linearGradient>
                </defs>
                <path d="M 80 80 L 155 80 A 75 75 0 0 0 80 5 Z" fill="url(#radarSweep)"></path>
                <circle className="animate-ping" cx="120" cy="45" fill="#6bd8cb" r="2.5"></circle>
                <circle cx="48" cy="115" fill="#adc6ff" r="2"></circle>
              </svg>

              <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
                <div className="w-full h-px bg-primary/10"></div>
                <div className="h-full w-px bg-primary/10 absolute"></div>
              </div>
              
              <div className="relative z-10 p-space-xs rounded-xl bg-surface-container shadow-md flex items-center justify-center transform hover:scale-105 transition-transform duration-300">
                <img alt="ARC Security Cyber Shield Logo" className="w-24 h-24 object-contain rounded-lg" src="https://lh3.googleusercontent.com/aida/AEtjO1V7c0ZYi_qcmNr_iF95rRV37IECqy-YHByiUfpjrZVfItV0DF1t9EqlVnHgL3q_VjgMe2e4YxuWxSYZJfTWmhkfA4HjsIBPFEtmZGoO8aZE3sD4DmvBV_QgGaSQG0FQNoM6GH8_GvAy6DF_m4UbI8Q-xgrAe8I-6M_ms4lOV05KVnumH0YWxRccw5Ot8TA7kTruoL7KDHbwjKE2wbOi6qEFbDDCNyFocBv5M9PASXdpcO0mIcZSzJSWr2b0" />
              </div>
            </div>

            <h1 className="font-headline-xl text-headline-xl text-on-surface tracking-tight font-bold mb-space-xs flex items-center gap-space-sm justify-center">
              <span>ARC WORKSTATION</span>
              <span className="inline-block px-2 py-0.5 rounded text-label-sm font-label-sm bg-primary/10 text-primary align-middle">PRO</span>
            </h1>
            <p className="font-label-md text-label-md text-on-surface-variant max-w-lg mx-auto uppercase tracking-wider">
              Adaptive Response &amp; Correlation Engine <span className="text-tertiary">v2.4.1 (x64)</span>
            </p>
            <p className="font-body-sm text-body-sm text-outline mt-1">
              Continuous Zero-Trust Telemetry Engine &amp; Multi-Tier SOC Controller
            </p>
          </div>

          {/* Telemetry Boot Meter & Progress Segment */}
          <div className="w-full max-w-2xl bg-surface-container-low rounded-xl p-space-md shadow-sm mb-space-md">
            <div className="flex items-center justify-between mb-space-xs">
              <div className="flex items-center gap-space-xs">
                <span className="font-label-sm text-label-sm text-on-surface uppercase">Subsystem Pipeline Initialization</span>
              </div>
              <div className="flex items-baseline gap-space-xs">
                <span className="font-label-lg text-label-lg font-bold text-primary">{currentPct}%</span>
                <span className="font-label-sm text-label-sm text-outline">EST. {((100 - currentPct) / 10).toFixed(1)}s</span>
              </div>
            </div>
            
            <div className="w-full bg-surface-container-lowest h-3 rounded-sm p-0.5 flex gap-1 items-center">
              <div className="h-full bg-primary rounded-xs transition-all duration-300 relative overflow-hidden" style={{ width: `${currentPct}%` }}>
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent animate-pulse"></div>
              </div>
              <div className="h-full flex-1 bg-surface-container rounded-xs"></div>
            </div>

            <div className="grid grid-cols-4 gap-space-xs mt-space-sm pt-space-xs text-center font-label-sm text-label-sm">
              <div className="flex items-center gap-1 justify-center text-tertiary">
                <span className="truncate">Kernel eBPF</span>
              </div>
              <div className="flex items-center gap-1 justify-center text-tertiary">
                <span className="truncate">IPC Broker</span>
              </div>
              <div className="flex items-center gap-1 justify-center text-primary font-medium">
                <span className="truncate">Sigma Rules</span>
              </div>
              <div className="flex items-center gap-1 justify-center text-outline">
                <span className="truncate">mTLS Mesh</span>
              </div>
            </div>
          </div>

          {/* Terminal Command Output Display Console */}
          <div className="w-full max-w-3xl bg-surface-container-lowest rounded-xl shadow-md overflow-hidden flex flex-col mb-space-md">
            <div className="px-space-md py-space-xs bg-surface-container flex items-center justify-between">
              <div className="flex items-center gap-space-sm">
                <div className="flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-error/70"></span>
                  <span className="w-2.5 h-2.5 rounded-full bg-secondary-container"></span>
                  <span className="w-2.5 h-2.5 rounded-full bg-tertiary/70"></span>
                </div>
                <span className="font-label-sm text-label-sm text-on-surface-variant font-medium ml-1">arc-init-daemon.sh — pts/1</span>
              </div>
              <div className="flex items-center gap-space-sm font-label-sm text-label-sm text-outline">
                <span className="hidden sm:inline">UTF-8</span>
                <span className="px-1.5 py-0.5 bg-surface-container-high rounded text-on-surface">LIVE FEED</span>
              </div>
            </div>
            
            <div ref={terminalRef} className="p-space-md font-label-sm text-label-sm space-y-1.5 min-h-[168px] overflow-y-auto bg-surface-container-lowest">
              {logs.map((log, i) => (
                <div key={i} className={`flex items-start gap-space-sm animate-fadeIn ${log.isDiagnostic ? 'text-error bg-error/10 p-1.5 rounded' : ''}`}>
                  <span className={`${log.color} font-bold`}>{log.tag}</span>
                  <span className="text-on-surface-variant">{log.text}</span>
                  <span className="text-outline ml-auto font-mono text-xs">{log.latency}</span>
                </div>
              ))}
            </div>
            
            <div className="px-space-md py-space-xs bg-surface-container flex items-center justify-between text-outline font-label-sm text-label-sm">
              <div className="flex items-center gap-space-xs">
                <span className="w-1.5 h-1.5 rounded-full bg-primary"></span>
                <span>MEMORY ALLOCATION: 412 MB / 16 GB</span>
              </div>
              <span className="font-mono text-xs">STATION LATENCY: 1.1ms</span>
            </div>
          </div>

          {/* Security Clearance Level & Diagnostics Trigger Footer */}
          <footer className="w-full flex flex-col sm:flex-row items-center justify-between gap-space-sm p-space-sm bg-surface-container-low rounded-lg shadow-sm">
            <div className="flex items-center gap-space-sm">
              <div className="px-space-sm py-1 rounded bg-error/10 text-error flex items-center gap-1.5">
                <span className="font-label-sm text-label-sm font-semibold tracking-wider">LEVEL-5 CLEARANCE</span>
              </div>
              <span className="font-body-sm text-body-sm text-on-surface-variant hidden md:inline">
                AUTHORIZED SOC PERSONNEL ONLY • STRICT AUDITING ENABLED
              </span>
            </div>
            <div className="flex items-center gap-space-sm w-full sm:w-auto justify-end">
              <button onClick={handleDiagnostic} className="w-full sm:w-auto px-space-md py-space-xs rounded bg-surface-container hover:bg-surface-container-high text-on-surface font-label-sm text-label-sm flex items-center justify-center gap-space-xs transition-colors">
                <span>[F2 ADVANCED DIAGNOSTICS]</span>
              </button>
              <button onClick={handleReset} className="px-space-md py-space-xs rounded bg-primary text-on-primary font-label-sm text-label-sm font-semibold hover:bg-primary-container transition-colors flex items-center gap-space-xs">
                <span>ABORT / RESET</span>
              </button>
            </div>
          </footer>
        </div>
      </div>
    </div>
  );
};

export default SplashScreen;
