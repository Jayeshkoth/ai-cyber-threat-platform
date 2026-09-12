import { useEffect, useState } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import "./App.css";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [statistics, setStatistics] = useState(null);
  const [history, setHistory] = useState([]);
  const [attackCategories, setAttackCategories] = useState({});
  const [threatHistory, setThreatHistory] = useState([]);
  const [threatTrends, setThreatTrends] = useState([]);
  const [repeatedUrls, setRepeatedUrls] = useState([]);
  const [increasedRiskUrls, setIncreasedRiskUrls] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [trendRange, setTrendRange] = useState("all");

  const formatConfidence = (value) => {
    const number = Number(value);

    if (Number.isNaN(number)) {
      return "N/A";
    }

    // Database stores confidence as decimal (0.9974)
    // API scan result may already return percentage (99.74)
    const percentage = number <= 1 ? number * 100 : number;

    return `${percentage.toFixed(2)}%`;
  };
    const parseStoredJson = (value) => {
    if (!value) {
      return null;
    }

    try {
      return typeof value === "string" ? JSON.parse(value) : value;
    } catch (error) {
      console.error("Failed to parse stored scan data:", error);
      return null;
    }
  };

  const loadDashboard = async () => {
    try {
      const [statsResponse, historyResponse, attackCategoriesResponse] =
  await Promise.all([
    fetch("http://127.0.0.1:8000/api/statistics"),
    fetch("http://127.0.0.1:8000/api/history"),
    fetch("http://127.0.0.1:8000/api/attack-category-distribution"),
  ]);

     if (
  !statsResponse.ok ||
  !historyResponse.ok ||
  !attackCategoriesResponse.ok
) {
  throw new Error("Failed to load dashboard data");
}

      const statsData = await statsResponse.json();
      const historyData = await historyResponse.json();
      const attackCategoriesData = await attackCategoriesResponse.json();

        setStatistics(statsData);
setHistory(historyData.scans || []);
setAttackCategories(attackCategoriesData);

const threatHistoryResponse = await fetch(
  "http://127.0.0.1:8000/api/threat-history"
);
const threatHistoryData = await threatHistoryResponse.json();



setThreatHistory(threatHistoryData.history || []);
const trendParams = new URLSearchParams();

if (trendRange !== "all") {
  const days = Number(trendRange);
  const endTime = new Date();
  const startTime = new Date();

  startTime.setDate(startTime.getDate() - days);

  trendParams.set("start_time", startTime.toISOString());
  trendParams.set("end_time", endTime.toISOString());
}

const trendUrl =
  trendRange === "all"
    ? "http://127.0.0.1:8000/api/threat-trends"
    : `http://127.0.0.1:8000/api/threat-trends?${trendParams.toString()}`;

const threatTrendsResponse = await fetch(trendUrl);

const threatTrendsData = await threatTrendsResponse.json();

setThreatTrends(threatTrendsData.trends || []);
const repeatedUrlsResponse = await fetch(
  "http://127.0.0.1:8000/api/repeated-urls"
);

const repeatedUrlsData = await repeatedUrlsResponse.json();
setRepeatedUrls(repeatedUrlsData.repeated_urls || []);
const increasedRiskResponse = await fetch(
  "http://127.0.0.1:8000/api/increased-risk-urls"
);
const alertsResponse = await fetch(
  "http://127.0.0.1:8000/api/alerts"
);
const alertsData = await alertsResponse.json();
setAlerts(alertsData.alerts || []);

const increasedRiskData = await increasedRiskResponse.json();
setIncreasedRiskUrls(increasedRiskData.increased_risk_urls || []);
  } catch (err) {
    console.error("Dashboard loading error:", err);
  }
};
  useEffect(() => {
  loadDashboard();
}, [trendRange]);


  const loadScanDetails = async (scanId) => {
    try {
      const response = await fetch(
        `http://127.0.0.1:8000/api/history/${scanId}`
      );

      if (!response.ok) {
        throw new Error("Failed to load scan details");
      }

      const data = await response.json();
      setSelectedScan(data);
    } catch (error) {
      console.error("Error loading scan details:", error);
    }
  };

  const scanUrl = async () => {
    setError("");
    setResult(null);

    if (!url.trim()) {
      setError("Please enter a URL.");
      return;
    }

    setLoading(true);

    try {
      const response = await fetch("http://127.0.0.1:8000/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          input: url.trim(),
          type: "url",
        }),
      });

      if (!response.ok) {
        throw new Error("Scan failed");
      }

      const data = await response.json();

      setResult(data);

      // Refresh statistics and recent scans
      await loadDashboard();
    } catch (err) {
      console.error(err);
      setError("Unable to scan the URL. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const maxAttackCategoryCount = Math.max(
  ...Object.values(attackCategories),
  1
);

  return (
    <div className="app-container">
      <header className="hero-section">
        <h1>AI Cyber Threat Platform</h1>
        <p>
          Analyze URLs using AI prediction, security analysis, and threat
          intelligence.
        </p>
      </header>

      <section className="scan-section">
        <div className="scan-input-container">
          <input
            type="text"
            placeholder="Enter URL"
            value={url}
            onChange={(event) => {
              setUrl(event.target.value);
              setError("");
            }}
            onKeyDown={(event) => {
              if (event.key === "Enter" && !loading) {
                scanUrl();
              }
            }}
          />

          <button onClick={scanUrl} disabled={loading}>
            {loading ? "Scanning..." : "Scan URL"}
          </button>
        </div>

        {error && <p className="error-message">{error}</p>}
      </section>

      {result && (
        <section
          className={`result-card ${
            result.prediction === "PHISHING" ? "phishing" : "legitimate"
          }`}
        >
          <div className="result-header">
            <span className="result-icon">
             {result.prediction === "PHISHING" ? "⚠️" : "✅"}
            </span>

            <h2>
              {result.prediction === "PHISHING" ? "PHISHING" : "SAFE URL"}
            </h2>
          </div>

          <div className="result-details">
            <p>
              <strong>URL:</strong> {result.url}
            </p>

            <p>
              <strong>Risk Score:</strong> {result.risk_score}/100
            </p>

            <p>
              <strong>Confidence:</strong>{" "}
              {formatConfidence(result.confidence)}
            </p>

            <p>
              <strong>Category:</strong> {result.category}
            </p>
          </div>

          <div className="analysis-section">
            <h3>Security Findings</h3>

            {result.findings &&
            Object.keys(result.findings).length > 0 ? (
              <ul>
                {Object.entries(result.findings).map(([key, value]) => (
                  <li key={key}>
                    <strong>{key}:</strong> {String(value)}
                  </li>
                ))}
              </ul>
            ) : (
              <p>No suspicious indicators detected.</p>
            )}
          </div>

          {result.threat_intelligence && (
            <div className="analysis-section">
              <h3>Threat Intelligence</h3>

              <p>
                <strong>Reputation:</strong>{" "}
                {result.threat_intelligence.reputation || "Unknown"}
              </p>

              <p>
                <strong>Blacklisted:</strong>{" "}
                {result.threat_intelligence.blacklisted ? "Yes" : "No"}
              </p>

              <p>
                <strong>Sources Checked:</strong>{" "}
                {Array.isArray(result.threat_intelligence.sources_checked)
                  ? result.threat_intelligence.sources_checked.join(", ")
                  : "None"}
              </p>

              {Array.isArray(result.threat_intelligence.details) &&
                result.threat_intelligence.details.length > 0 && (
                  <div className="provider-results">
                    <h4>Provider Results</h4>

                    <ul>
                      {result.threat_intelligence.details.map(
                        (provider, index) => (
                          <li key={index}>
                            <strong>
                              {provider.source || "Provider"}:
                            </strong>{" "}
                            {provider.status || "unknown"}
                            {provider.malicious === true &&
  "— Malicious"}

{provider.malicious === false &&
  "— No malicious detection"}

{provider.malicious === null &&
  "— No determination"}
                          </li>
                        )
                      )}
                    </ul>
                  </div>
                )}
            </div>
          )}

          {result.attack_prediction && (
            <div className="analysis-section">
              <h3>AI Attack Prediction</h3>

              <p>
                <strong>Attack Category:</strong>{" "}
                {result.attack_prediction.attack_category}
              </p>

              <p>
                <strong>Attack Likelihood:</strong>{" "}
                {result.attack_prediction.attack_likelihood}/100
              </p>

              <p>
                <strong>Severity:</strong>{" "}
                {result.attack_prediction.severity}
              </p>

              {Array.isArray(result.attack_prediction.evidence) &&
                result.attack_prediction.evidence.length > 0 && (
                  <div className="provider-results">
                    <h4>Prediction Evidence</h4>

                    <ul>
                      {result.attack_prediction.evidence.map(
                        (item, index) => (
                          <li key={index}>{item}</li>
                        )
                      )}
                    </ul>
                  </div>
                )}
            </div>
          )}
          {result.alert && (
  <div className={`provider-results alert-${result.alert.severity.toLowerCase()}`}>
    <h3>Security Alert</h3>

    <p>
      <strong>Alert:</strong>{" "}
      {result.alert.alert ? "Triggered" : "No Alert"}
    </p>

    <p>
      <strong>Severity:</strong>{" "}
      {result.alert.severity}
    </p>

    <p>
      <strong>Risk Score:</strong>{" "}
      {result.alert.risk_score}
    </p>

    <p>
      <strong>Message:</strong>{" "}
      {result.alert.message}
    </p>
  </div>
)}
        </section>
      )}

      {statistics && (

        <section className="dashboard-section">
          <h2>Scan Statistics</h2>

          <div className="statistics-grid">
            <div className="stat-card">
              <h3>Total Scans</h3>
              <strong>{statistics.total_scans}</strong>
            </div>

            <div className="stat-card">
              <h3>Phishing Detected</h3>
              <strong>{statistics.phishing_count}</strong>

              {statistics.total_scans > 0 && (
                <span>
                  {(
                    (statistics.phishing_count / statistics.total_scans) *
                    100
                  ).toFixed(1)}
                  % of scans
                </span>
              )}
            </div>

            <div className="stat-card">
              <h3>Legitimate URLs</h3>
              <strong>{statistics.legitimate_count}</strong>

              {statistics.total_scans > 0 && (
                <span>
                  {(
                    (statistics.legitimate_count / statistics.total_scans) *
                    100
                  ).toFixed(1)}
                  % of scans
                </span>
              )}
            </div>
          </div>
        </section>
      )}
      <div className="section">
  <h2>Attack Category Distribution</h2>
  

  <div className="attack-category-grid">
  {Object.entries(attackCategories).map(([category, count]) => (
    <div className="stat-card" key={category}>
      <h3>{category}</h3>
      <p>{count}</p>

      <div className="attack-bar">
        <div
          className="attack-bar-fill"
          style={{
            width: `${(count / maxAttackCategoryCount) * 100}%`,
          }}
        />
      </div>
    </div>
  ))}
</div>
</div>

<section className="history-section">
 <h2>Threat Trends</h2>

<div className="threat-trends-controls">
  <label htmlFor="trend-range">Time Range:</label>

  <select
  id="trend-range"
  value={trendRange}
  onChange={(event) => setTrendRange(event.target.value)}
>
    <option value="all">All Time</option>
    <option value="7">Last 7 Days</option>
    <option value="30">Last 30 Days</option>
  </select>
</div>
<div className="threat-trend-chart">
  <ResponsiveContainer width="100%" height={300}>
    <LineChart data={threatTrends}>
      <CartesianGrid strokeDasharray="3 3" />
      <XAxis dataKey="date" />
      <YAxis allowDecimals={false} />
      <Tooltip />
      <Legend />
      <Line
  type="monotone"
  dataKey="LEGITIMATE"
  name="Legitimate"
  stroke="#388e3c"
  strokeWidth={4}
  dot={{ r: 5 }}
/>
      <Line
        type="monotone"
        dataKey="PHISHING"
        name="Phishing"
        stroke="#d32f2f"
         strokeWidth={4}
          dot={{ r: 5 }}
       />
    </LineChart>
  </ResponsiveContainer>
</div>

<div className="threat-trends">
  <div className="trend-header">
    <strong>Date</strong>
    <strong>Phishing</strong>
    <strong>Legitimate</strong>
  </div>

  {threatTrends.map((item, index) => (
    <div className="trend-row" key={index}>
      <span>{item.date}</span>
      <span>{item.PHISHING}</span>
      <span>{item.LEGITIMATE}</span>
    </div>
  ))}
</div>
<h2>Alerts</h2>

<div className="alerts-section">
  {alerts.length > 0 ? (
    alerts.map((alert, index) => (
      <div
        className={`alert-card alert-${alert.severity.toLowerCase()}`}
        key={index}
      >
        <h3>{alert.url}</h3>

        <p>
          <strong>Severity:</strong> {alert.severity}
        </p>

        <p>
          <strong>Risk Score:</strong> {alert.risk_score}
        </p>

        <p>
          <strong>Prediction:</strong> {alert.prediction}
        </p>

        <p>
          <strong>Message:</strong> {alert.message}
        </p>

        <small>
          Scan ID: {alert.scan_id}
          <br />
          {new Date(alert.timestamp).toLocaleString()}
        </small>
      </div>
    ))
  ) : (
    <p>No active alerts.</p>
  )}
</div>
<h2>Increased-Risk URLs</h2>
<div className="increased-risk-urls">
  {increasedRiskUrls.map((item, index) => (
    <div className="stat-card" key={index}>
      <h3>{item.url}</h3>
      <p>
        Risk: {(item.first_risk * 100).toFixed(0)}% →{" "}
        {(item.latest_risk * 100).toFixed(0)}%
      </p>
      <p>
        Increase: +{(item.risk_increase * 100).toFixed(0)}%
      </p>
      <small>
        First seen: {new Date(item.first_seen).toLocaleString()}
        <br />
        Last seen: {new Date(item.last_seen).toLocaleString()}
      </small>
    </div>
  ))}
</div>
<h2>Repeated URLs</h2>
<div className="repeated-urls">
  {repeatedUrls.slice(0, 10).map((item, index) => (
    <div className="stat-card" key={index}>
      <h3>{item.url}</h3>
      <p>Scans: {item.scan_count}</p>
      <small>
        First seen: {new Date(item.first_seen).toLocaleString()}
        <br />
        Last seen: {new Date(item.last_seen).toLocaleString()}
      </small>
    </div>
  ))}
</div>
  <h2>Threat History</h2>
  <p>Showing latest 10 of {threatHistory.length} records</p>

<div className="threat-history">
  {threatHistory.slice(-10).reverse().map((item, index) => (
    <div className="stat-card" key={index}>
      
      <h3>{item.prediction}</h3>
<p>{item.url}</p>
<small>{new Date(item.timestamp).toLocaleString()}</small>
    </div>
  ))}
</div>
        <h2>Recent Scans</h2>

        <div className="history-list">
          {history.length === 0 ? (
            <p className="empty-history">No scans yet.</p>
          ) : (
            history.map((scan) => (
              <div
                className="history-card"
                key={scan.id}
                onClick={() => loadScanDetails(scan.id)}
                 onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                loadScanDetails(scan.id);
                   }
                   }}
                    role="button"
                    tabIndex={0}
                     >
                <div className="history-main">
                  <div>
                    <strong>{scan.url}</strong>

                    <span className="scan-number">
                      Scan #{scan.id}
                    </span>
                  </div>

                  <span
                    className={`history-status ${
                      scan.prediction === "PHISHING"
                        ? "phishing"
                        : "legitimate"
                    }`}
                  >
                    {scan.prediction}
                  </span>
                </div>

                <div className="history-details">
                  <span>
                    Confidence: {formatConfidence(scan.confidence)}
                  </span>

                  <span>
                    {scan.timestamp
                      ? new Date(scan.timestamp).toLocaleString()
                      : "Unknown time"}
                  </span>
                </div>
              </div>
            ))
          )}
        </div>
        {selectedScan && (
  <div className="scan-details-card">
    <div className="scan-details-header">
      <h3>Scan Details</h3>

      <button
        type="button"
        onClick={() => setSelectedScan(null)}
      >
        Close
      </button>
    </div>

    <div className="scan-details-content">
  {(() => {
    const securityAnalysis = parseStoredJson(selectedScan.security_analysis);
    const threatIntelligence = parseStoredJson(
      selectedScan.threat_intelligence
    );
    const attackPrediction = securityAnalysis?.attack_prediction;
    const alert = securityAnalysis?.alert;

    return (
      <>
        <div className="detail-item">
          <strong>URL</strong>
          <span>{selectedScan.url}</span>
        </div>

        <div className="detail-item">
          <strong>Prediction</strong>
          <span>{selectedScan.prediction}</span>
        </div>

        <div className="detail-item">
          <strong>Confidence</strong>
          <span>{formatConfidence(selectedScan.confidence)}</span>
        </div>

        {securityAnalysis && (
          <>
            <div className="detail-item">
              <strong>Risk Score</strong>
              <span>{securityAnalysis.risk_score ?? "N/A"}</span>
            </div>

            <div className="detail-section">
              <h4>Security Findings</h4>

              {securityAnalysis.findings?.length ? (
                <ul>
                  {securityAnalysis.findings.map((finding, index) => (
                    <li key={index}>{finding}</li>
                  ))}
                </ul>
              ) : (
                <p>No security findings.</p>
              )}
            </div>
          </>
        )}

        {attackPrediction && (
          <div className="detail-section">
            <h4>Attack Prediction</h4>

            <div className="detail-item">
              <strong>Category</strong>
              <span>{attackPrediction.attack_category}</span>
            </div>

            <div className="detail-item">
              <strong>Likelihood</strong>
              <span>{attackPrediction.attack_likelihood}%</span>
            </div>

            <div className="detail-item">
              <strong>Severity</strong>
              <span>{attackPrediction.severity}</span>
            </div>

            <h4>Evidence</h4>

            {attackPrediction.evidence?.length ? (
              <ul>
                {attackPrediction.evidence.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            ) : (
              <p>No evidence recorded.</p>
            )}
          </div>
        )}

        {threatIntelligence && (
          <div className="detail-section">
            <h4>Threat Intelligence</h4>

            <div className="detail-item">
              <strong>Reputation</strong>
              <span>{threatIntelligence.reputation}</span>
            </div>

            <div className="detail-item">
              <strong>Blacklisted</strong>
              <span>
                {threatIntelligence.blacklisted ? "Yes" : "No"}
              </span>
            </div>

            <div className="detail-item">
              <strong>Sources Checked</strong>
              <span>
                {threatIntelligence.sources_checked?.join(", ") || "None"}
              </span>
            </div>
           </div>
        )}
        {alert && (
  <div className={`detail-section alert-${alert.severity.toLowerCase()}`}>
    <h4>Security Alert</h4>

    <div className="detail-item">
      <strong>Alert</strong>
      <span>{alert.alert ? "Triggered" : "No Alert"}</span>
    </div>

    <div className="detail-item">
      <strong>Severity</strong>
      <span>{alert.severity}</span>
    </div>

    <div className="detail-item">
      <strong>Risk Score</strong>
      <span>{alert.risk_score}</span>
    </div>

    <div className="detail-item">
      <strong>Message</strong>
      <span>{alert.message}</span>
    </div>
  </div>
)}
      </>
    );
  })()}
</div>
  </div>
)}
      </section>
    </div>
  );
}

export default App;

