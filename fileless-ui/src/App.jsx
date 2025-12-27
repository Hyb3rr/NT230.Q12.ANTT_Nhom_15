import { useCallback, useEffect, useMemo, useState } from 'react'
import './App.css'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000'
const stagePalette = ['#7fb8ff', '#9ddfbc', '#f7d483', '#f5a4b7']
const POLL_INTERVAL = 5000

function ProbabilityBar({ label, value, color }) {
  const width = Math.max(2, Math.round((value || 0) * 100))
  return (
    <div className="prob-row">
      <div className="prob-label">{label}</div>
      <div className="prob-meter">
        <div className="prob-fill" style={{ width: `${width}%`, background: color }} />
      </div>
      <div className="prob-value">{((value || 0) * 100).toFixed(1)}%</div>
    </div>
  )
}

function ResultCard({ result, onTechniqueClick }) {
  if (!result) return null
  const verdictTone = result.verdict === 'malicious' ? 'bad' : 'good'
  const probabilities = Object.entries(result.probabilities || {})

  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">Analysis result</p>
          <h2>{result.stage_name} stage</h2>
          <p className="muted">Verdict: <span className={`chip ${verdictTone}`}>{result.verdict}</span></p>
        </div>
        <div className="stats">
          <div>
            <p className="stat-label">Confidence</p>
            <p className="stat-value">{(result.confidence * 100).toFixed(2)}%</p>
          </div>
          <div>
            <p className="stat-label">Inference</p>
            <p className="stat-value">{result.inference_time_ms ?? '—'} ms</p>
          </div>
        </div>
      </div>

      <div className="prob-grid">
        {probabilities.map(([label, value], idx) => (
          <ProbabilityBar key={label} label={label} value={value} color={stagePalette[idx] || '#cbd5ff'} />
        ))}
      </div>

      <div className="tags">
        {(result.tactics || []).map((t) => (
          <span key={t} className="pill subtle">{t}</span>
        ))}
      </div>

      <div className="techniques">
        <p className="eyebrow">Common techniques</p>
        <div className="tag-row">
          {(result.common_techniques || []).map((tech) => (
            <button key={tech} className="pill action" onClick={() => onTechniqueClick?.(tech)}>
              {tech}
            </button>
          ))}
        </div>
      </div>

      <div className="recommendation">
        <p className="eyebrow">Recommendation</p>
        <p>{result.recommendation}</p>
        {result.warning ? <p className="warning">⚠ {result.warning}</p> : null}
      </div>
    </section>
  )
}

function StageBoard({ stages }) {
  const list = useMemo(() => Object.values(stages || {}), [stages])
  if (!list.length) return null
  return (
    <section className="panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">Stage reference</p>
          <h3>ATT&CK stages (0-3)</h3>
        </div>
      </div>
      <div className="stage-grid">
        {list.map((stage) => (
          <div key={stage.stage_id} className="stage-card">
            <div className="stage-id">{stage.stage_id}</div>
            <div>
              <p className="stage-name">{stage.stage_name}</p>
              <p className="muted">{stage.description}</p>
              <div className="tag-row">
                {stage.tactics.map((t) => (
                  <span key={t} className="pill subtle">{t}</span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </section>
  )
}

function TechniqueDrawer({ item, onClose }) {
  if (!item) return null
  return (
    <div className="drawer">
      <div className="drawer-card">
        <div className="drawer-head">
          <div>
            <p className="eyebrow">MITRE ATT&CK</p>
            <h3>{item.name}</h3>
            <p className="muted">{item.tactic}</p>
          </div>
          <button className="pill action" onClick={onClose}>Close</button>
        </div>
        <p>{item.description}</p>
        <p className="muted">Detection: {item.detection}</p>
      </div>
    </div>
  )
}

function MonitoringStats({ stats, status }) {
  if (!stats) return null
  const isActive = status === 'active'
  return (
    <section className="panel stats-panel">
      <div className="panel-head">
        <div>
          <p className="eyebrow">Real-time Monitoring</p>
          <h3>Process Scanner Statistics</h3>
        </div>
        <div className={`status-badge ${isActive ? 'active' : 'inactive'}`}>
          {isActive ? '🟢 Active' : '🔴 Inactive'}
        </div>
      </div>

      <div className="stats-grid">
        <div className="stat-box">
          <div className="stat-icon">🔍</div>
          <div className="stat-number">{stats.total_scanned || 0}</div>
          <div className="stat-label">Processes Scanned</div>
        </div>
        <div className="stat-box warning">
          <div className="stat-icon">⚠️</div>
          <div className="stat-number">{stats.suspicious_found || 0}</div>
          <div className="stat-label">Suspicious Found</div>
        </div>
        <div className="stat-box danger">
          <div className="stat-icon">🚨</div>
          <div className="stat-number">{stats.malware_detected || 0}</div>
          <div className="stat-label">Malware Detected</div>
        </div>
        <div className="stat-box success">
          <div className="stat-icon">✅</div>
          <div className="stat-number">{stats.benign_processes || 0}</div>
          <div className="stat-label">Benign Processes</div>
        </div>
      </div>

      <div className="queue-info">
        <span>Analysis Queue: <strong>{stats.queue_size || 0}</strong> pending</span>
        <span>Monitored PIDs: <strong>{stats.monitored_pids || 0}</strong></span>
      </div>
    </section>
  )
}

function DetectionCard({ detection, onTechniqueClick }) {
  if (!detection) return null
  const proc = detection.process_info || {}
  const verdictTone = detection.verdict === 'malicious' ? 'bad' : 'good'
  const ts = detection.timestamp ? new Date(detection.timestamp).toLocaleString() : '—'

  return (
    <section className="panel detection-card">
      <div className="panel-head">
        <div>
          <p className="eyebrow">{proc.name || 'Unknown process'} (PID: {proc.pid ?? 'N/A'})</p>
          <h3>{detection.stage_name || 'Unknown stage'}</h3>
          <p className="muted">{ts}</p>
        </div>
        <div className={`chip ${verdictTone}`}>{detection.verdict}</div>
      </div>

      <div className="stats">
        <div>
          <p className="stat-label">Confidence</p>
          <p className="stat-value">{(detection.confidence * 100).toFixed(2)}%</p>
        </div>
        {detection.memory_dump && (
          <div>
            <p className="stat-label">Memory dump</p>
            <p className="stat-value">{detection.memory_dump.split(/[/\\]/).pop()}</p>
          </div>
        )}
        {detection.enhanced_confidence !== undefined && (
          <div>
            <p className="stat-label">Post-Volatility</p>
            <p className="stat-value">{(detection.enhanced_confidence * 100).toFixed(2)}%</p>
          </div>
        )}
      </div>

      <div className="detection-details">
        <p><strong>Path:</strong> <code>{proc.exe_path || 'N/A'}</code></p>
        <p><strong>Command:</strong> <code>{(proc.cmdline || 'N/A').slice(0, 180)}</code></p>
        {proc.parent_name && (
          <p><strong>Parent:</strong> {proc.parent_name} (PID: {proc.parent_pid})</p>
        )}
      </div>

      <div className="tags">
        {(detection.tactics || []).map((t) => (
          <span key={t} className="pill subtle">{t}</span>
        ))}
      </div>

      <div className="techniques">
        <p className="eyebrow">MITRE ATT&CK Techniques</p>
        <div className="tag-row">
          {(detection.common_techniques || []).map((tech) => (
            <button key={tech} className="pill action" onClick={() => onTechniqueClick?.(tech)}>
              {tech}
            </button>
          ))}
        </div>
      </div>

      {detection.memory_indicators && (
        <div className="recommendation">
          <p className="eyebrow">Volatility highlights</p>
          <p>APIs: {detection.memory_indicators.api_calls?.length || 0} · Injection patterns: {detection.memory_indicators.injection_patterns || 0} · Obfuscation: {detection.memory_indicators.obfuscation_score}</p>
        </div>
      )}

      {detection.recommendation && (
        <div className="recommendation">
          <p className="eyebrow">Recommendation</p>
          <p>{detection.recommendation}</p>
        </div>
      )}
    </section>
  )
}

function DetectionsList({ detections, onTechniqueClick }) {
  if (!detections || detections.length === 0) {
    return (
      <div className="empty-state">
        <p>No malware detections yet. System is monitoring...</p>
      </div>
    )
  }

  return (
    <div className="detections-list">
      {detections.map((detection, index) => (
        <DetectionCard key={index} detection={detection} onTechniqueClick={onTechniqueClick} />
      ))}
    </div>
  )
}

function App() {
  const [text, setText] = useState(`Process: powershell.exe
Command: powershell.exe -encodedcommand ...
Registry: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`)
  const [threshold, setThreshold] = useState(0.5)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)

  const [monitorStats, setMonitorStats] = useState(null)
  const [monitorStatus, setMonitorStatus] = useState('inactive')
  const [detections, setDetections] = useState([])
  const [monitorError, setMonitorError] = useState('')
  const [controlLoading, setControlLoading] = useState(false)

  const [activeTab, setActiveTab] = useState('monitor')
  const [stages, setStages] = useState({})
  const [techDetail, setTechDetail] = useState(null)

  useEffect(() => {
    fetch(`${API_BASE}/stages`).then((res) => res.json()).then(setStages).catch(() => {})
  }, [])

  const fetchMonitorStats = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/monitor/stats`)
      if (res.ok) {
        const data = await res.json()
        setMonitorStats(data.monitoring_stats)
        setMonitorStatus(data.status)
        setMonitorError('')
      }
    } catch (e) {
      setMonitorError('Failed to fetch stats')
    }
  }, [])

  const fetchDetections = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/monitor/detections`)
      if (res.ok) {
        const data = await res.json()
        setDetections(data.detections || [])
      }
    } catch (e) {
      console.error('Failed to fetch detections:', e)
    }
  }, [])

  const startMonitoring = async () => {
    setControlLoading(true)
    setMonitorError('')
    try {
      const res = await fetch(`${API_BASE}/monitor/start`, { method: 'POST' })
      if (res.ok) {
        await fetchMonitorStats()
      } else {
        const data = await res.json().catch(() => ({}))
        setMonitorError(data.detail || 'Failed to start monitoring')
      }
    } catch (e) {
      setMonitorError(e.message)
    } finally {
      setControlLoading(false)
    }
  }

  const stopMonitoring = async () => {
    setControlLoading(true)
    setMonitorError('')
    try {
      const res = await fetch(`${API_BASE}/monitor/stop`, { method: 'POST' })
      if (res.ok) {
        await fetchMonitorStats()
      } else {
        const data = await res.json().catch(() => ({}))
        setMonitorError(data.detail || 'Failed to stop monitoring')
      }
    } catch (e) {
      setMonitorError(e.message)
    } finally {
      setControlLoading(false)
    }
  }

  useEffect(() => {
    if (activeTab === 'monitor') {
      fetchMonitorStats()
      fetchDetections()
      const interval = setInterval(() => {
        fetchMonitorStats()
        fetchDetections()
      }, POLL_INTERVAL)
      return () => clearInterval(interval)
    }
  }, [activeTab, fetchMonitorStats, fetchDetections])

  const runDetect = async () => {
    setError('')
    setLoading(true)
    setResult(null)
    try {
      const payload = { text, threshold: Number(threshold) || 0.5 }
      const res = await fetch(`${API_BASE}/detect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })

      if (!res.ok) {
        const detail = await res.json().catch(() => ({}))
        throw new Error(detail.detail || `Request failed (${res.status})`)
      }
      const data = await res.json()
      setResult(data)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  const fetchTechnique = async (tid) => {
    setTechDetail(null)
    try {
      const res = await fetch(`${API_BASE}/techniques/${tid}`)
      if (res.ok) {
        const data = await res.json()
        setTechDetail({ id: tid, ...data })
      }
    } catch (e) {
      console.error(e)
    }
  }

  return (
    <div className="page">
      <header className="hero">
        <div>
          <p className="eyebrow">Argus · Fileless Defender v2.0</p>
          <h1>Real-time Process Monitoring Dashboard</h1>
          <p className="muted">Automatic Windows process scanning with BERT-MLP detection and MITRE ATT&CK correlation</p>
        </div>
        <div className="badge">API: {API_BASE}</div>
      </header>

      <div className="tab-nav">
        <button className={`tab ${activeTab === 'monitor' ? 'active' : ''}`} onClick={() => setActiveTab('monitor')}>
          🔍 Live Monitoring
        </button>
        <button className={`tab ${activeTab === 'manual' ? 'active' : ''}`} onClick={() => setActiveTab('manual')}>
          📝 Manual Analysis
        </button>
      </div>

      {activeTab === 'monitor' && (
        <div className="monitor-view">
          <section className="panel control-panel">
            <div className="panel-head">
              <div>
                <p className="eyebrow">Process Monitor Control</p>
                <h3>Start/Stop Real-time Scanning</h3>
              </div>
            </div>
            <div className="control-actions">
              <button className="cta success" onClick={startMonitoring} disabled={controlLoading || monitorStatus === 'active'}>
                {controlLoading ? '⏳ Starting...' : '▶️ Start Monitoring'}
              </button>
              <button className="cta danger" onClick={stopMonitoring} disabled={controlLoading || monitorStatus === 'inactive'}>
                {controlLoading ? '⏳ Stopping...' : '⏸️ Stop Monitoring'}
              </button>
              {monitorError && <span className="error">{monitorError}</span>}
            </div>
            <div className="control-info">
              <p className="muted">
                {monitorStatus === 'active'
                  ? '✅ System is actively scanning Windows processes every 2 seconds'
                  : '⏸️ Monitoring is paused. Click Start to begin scanning'}
              </p>
            </div>
          </section>

          <MonitoringStats stats={monitorStats} status={monitorStatus} />
          <DetectionsList detections={detections} onTechniqueClick={fetchTechnique} />
        </div>
      )}

      {activeTab === 'manual' && (
        <main className="layout">
          <section className="panel form">
            <div className="panel-head">
              <div>
                <p className="eyebrow">Input</p>
                <h3>Manual Log / Artifact Analysis</h3>
              </div>
            </div>
            <label className="field">
              <span>Text / memory artifact</span>
              <textarea value={text} onChange={(e) => setText(e.target.value)} rows={8} placeholder="Paste log or behavioral string..." />
            </label>
            <label className="field inline">
              <span>Threshold</span>
              <input type="number" step="0.05" min="0" max="1" value={threshold} onChange={(e) => setThreshold(e.target.value)} />
            </label>
            <div className="actions">
              <button className="cta" onClick={runDetect} disabled={loading || !text.trim()}>
                {loading ? 'Analyzing…' : 'Analyze'}
              </button>
              {error ? <span className="error">{error}</span> : null}
            </div>
          </section>

          <ResultCard result={result} onTechniqueClick={fetchTechnique} />
        </main>
      )}

      <StageBoard stages={stages} />
      <TechniqueDrawer item={techDetail} onClose={() => setTechDetail(null)} />
    </div>
  )
}

export default App
