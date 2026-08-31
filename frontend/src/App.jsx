import { useState } from "react";
import "./App.css";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const scanURL = async () => {
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
          input: url,
          type: "url",
        }),
      });

      if (!response.ok) {
        throw new Error("Scan failed");
      }

      const data = await response.json();

      setResult(data);
    } catch (err) {
      setError("Unable to scan the URL. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h1>AI Cyber Threat Platform</h1>

      <p>
        Enter a URL to check whether it is safe or suspicious.
      </p>

      <input
        type="text"
        placeholder="Enter URL"
        value={url}
        onChange={(event) => {
          setUrl(event.target.value);
          setError("");
        }}
      />

      <button onClick={scanURL}>
        {loading ? "Scanning..." : "Scan URL"}
      </button>

      {error && <p className="error-message">{error}</p>}

      {result && (
        <div
          className={`result-card ${
            result.threat === "malicious"
              ? "phishing"
              : "legitimate"
          }`}
        >
          <h2>
            {result.threat === "malicious"
              ? "⚠️ MALICIOUS"
              : "✅ SAFE"}
          </h2>

          <p>
            <strong>URL:</strong> {result.url}
          </p>

          <p>
            <strong>Risk Score:</strong> {result.risk_score}/100
          </p>

          <p>
            <strong>Confidence:</strong> {result.confidence}%
          </p>

          <p>
            <strong>Category:</strong> {result.category}
          </p>

          {/* --------------------------------------------- */}
          {/* SECURITY FINDINGS */}
          {/* --------------------------------------------- */}

          {result.findings && result.findings.length > 0 && (
            <div>
              <h3>Security Findings</h3>

              <ul>
                {result.findings.map((finding, index) => (
                  <li key={index}>{finding}</li>
                ))}
              </ul>
            </div>
          )}

          {result.findings && result.findings.length === 0 && (
            <p>
              <strong>Security Findings:</strong> No suspicious
              indicators detected.
            </p>
          )}

          {/* --------------------------------------------- */}
          {/* THREAT INTELLIGENCE */}
          {/* --------------------------------------------- */}

          {result.threat_intelligence && (
            <div className="threat-intelligence">
              <h3>Threat Intelligence</h3>

              <p>
                <strong>Reputation:</strong>{" "}
                {result.threat_intelligence.reputation}
              </p>

              <p>
                <strong>Blacklisted:</strong>{" "}
                {result.threat_intelligence.blacklisted
                  ? "Yes"
                  : "No"}
              </p>

              <p>
                <strong>Sources Checked:</strong>{" "}
                {result.threat_intelligence.sources_checked &&
                result.threat_intelligence.sources_checked.length > 0
                  ? result.threat_intelligence.sources_checked.join(
                      ", "
                    )
                  : "None"}
              </p>

              {result.threat_intelligence.details &&
                result.threat_intelligence.details.length > 0 && (
                  <div>
                    <h4>Provider Results</h4>

                    <ul>
                      {result.threat_intelligence.details.map(
                        (detail, index) => (
                          <li key={index}>
                            <strong>
                              {detail.source || "Provider"}:
                            </strong>{" "}
                            {detail.status || "unknown"}

                            {detail.malicious === true && (
                              <span> — Malicious</span>
                            )}

                            {detail.malicious === false && (
                              <span> — No malicious detection</span>
                            )}

                            {detail.malicious === null && (
                              <span> — No determination</span>
                            )}
                          </li>
                        )
                      )}
                    </ul>
                  </div>
                )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default App;