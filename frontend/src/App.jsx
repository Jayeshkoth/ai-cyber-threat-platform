import { useState } from "react";
import "./App.css";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

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

     <button
  onClick={async () => {
  setError("");
  setResult(null);

  if (!url.trim()) {
    setError("Please enter a URL.");
    return;
  }

  setLoading(true);

    try {
      const response = await fetch("http://127.0.0.1:8000/predict", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();

      setResult(data);
    } catch (err) {
      setError("Unable to scan the URL. Please try again.");
    } finally {
      setLoading(false);
    }
  }}
>
  {loading ? "Scanning..." : "Scan URL"}
</button>
        {error && <p className="error-message">{error}</p>}
         {result && (
       <div
  className={`result-card ${
    result.prediction === "PHISHING" ? "phishing" : "legitimate"
  }`}
>
          <h2>{result.prediction === "PHISHING" ? "⚠️ PHISHING" : "✅ LEGITIMATE"}</h2>
          
          <p>Confidence: {result.confidence}%</p>
        </div>
      )}
    </div>
  );
}

export default App;