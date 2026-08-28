import { useState } from "react";

function App() {
  const [url, setUrl] = useState("");

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
        onChange={(event) => setUrl(event.target.value)}
      />

     <button
  onClick={async () => {
    const response = await fetch("http://127.0.0.1:8000/predict", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url }),
    });

    const data = await response.json();

    console.log(data);
  }}
>
  Scan URL
</button>
    </div>
  );
}

export default App;