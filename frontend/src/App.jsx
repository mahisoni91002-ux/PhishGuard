import { useState } from "react";
import "./App.css";

const API_URL = "https://phishguard-api-4axc.onrender.com";

function App() {
  const [email, setEmail] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const analyzeEmail = async () => {
    if (!email.trim()) {
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const response = await fetch(`${API_URL}/api/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          text: email,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Analysis failed");
      }

      setResult(data);
    } catch (error) {
      setResult({
        error:
          "Could not connect to the PhishGuard backend. Make sure the FastAPI server is running.",
      });
    } finally {
      setLoading(false);
    }
  };

  const clearEmail = () => {
    setEmail("");
    setResult(null);
  };

  const loadPhishingExample = () => {
    setEmail(
      "URGENT! Your bank account has been suspended. Verify your password and OTP immediately using this link."
    );
    setResult(null);
  };

  const loadLegitimateExample = () => {
    setEmail(
      "Hello, your monthly electricity bill is ready. Please log in to the official portal to view your bill."
    );
    setResult(null);
  };

  const getRiskClass = (level) => {
    if (level === "High") return "risk-high";
    if (level === "Medium") return "risk-medium";
    return "risk-low";
  };

  return (
    <div className="app">
      <header className="navbar">
        <div className="brand">
          <div className="brand-icon">🛡️</div>
          <div>
            <h2>PhishGuard</h2>
            <span>AI-Powered Email Security</span>
          </div>
        </div>

        <div className="status">
          <span className="status-dot"></span>
          System Online
        </div>
      </header>

      <main>
        <section className="hero">
          <div className="hero-badge">AI + NLP + MACHINE LEARNING</div>

          <h1>
            Detect phishing before
            <span> it catches you.</span>
          </h1>

          <p>
            Analyze suspicious emails using Machine Learning and intelligent
            phishing-indicator detection.
          </p>
        </section>

        <section className="analyzer-card">
          <div className="card-header">
            <div>
              <h2>Analyze an Email</h2>
              <p>Paste the email content below to check its phishing risk.</p>
            </div>

            <span className="secure-badge">🔒 Secure Analysis</span>
          </div>

          <textarea
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Paste suspicious email content here..."
            maxLength={5000}
          />

          <div className="input-footer">
            <span>{email.length}/5000 characters</span>

            <button className="clear-btn" onClick={clearEmail}>
              Clear
            </button>
          </div>

          <div className="demo-buttons">
            <span>Try an example:</span>

            <button onClick={loadPhishingExample}>
              🔴 Phishing Example
            </button>

            <button onClick={loadLegitimateExample}>
              🟢 Legitimate Example
            </button>
          </div>

          <button
            className="analyze-btn"
            onClick={analyzeEmail}
            disabled={loading || !email.trim()}
          >
            {loading ? "Analyzing Email..." : "🔍 Analyze Email"}
          </button>
        </section>

        {result && !result.error && (
          <section className="results-section">
            <div className="result-header">
              <div>
                <span className="section-label">ANALYSIS RESULT</span>
                <h2>Email Security Report</h2>
              </div>

              <div
                className={`classification ${getRiskClass(
                  result.risk_level
                )}`}
              >
                {result.classification}
              </div>
            </div>

            <div className="result-grid">
              <div className="score-card">
                <span className="card-label">PHISHING RISK SCORE</span>

                <div className="score-circle">
                  <strong>{result.risk_score}</strong>
                  <small>/100</small>
                </div>

                <div
                  className={`risk-label ${getRiskClass(result.risk_level)}`}
                >
                  {result.risk_level} Risk
                </div>
              </div>

              <div className="confidence-card">
                <span className="card-label">ML PHISHING SCORE</span>

                <div className="confidence-number">
                  {result.ml_confidence}%
                </div>

                <div className="progress-bar">
                  <div
                    className="progress-fill"
                    style={{
                      width: `${result.ml_confidence}%`,
                    }}
                  ></div>
                </div>

                <p>
                  Estimated score from the trained TF-IDF + Naive Bayes model.
                </p>
              </div>
            </div>

            <div className="indicators-card">
              <div className="card-title-row">
                <div>
                  <span className="section-label">WHY THIS RESULT?</span>
                  <h3>Detected Indicators</h3>
                </div>

                <span className="indicator-count">
                  {result.indicators.length} detected
                </span>
              </div>

              {result.indicators.length === 0 ? (
                <div className="no-indicators">
                  <span>✓</span>
                  <div>
                    <strong>No major indicators detected</strong>
                    <p>
                      The system did not find the predefined phishing
                      indicators in this email.
                    </p>
                  </div>
                </div>
              ) : (
                <div className="indicator-list">
                  {result.indicators.map((indicator, index) => (
                    <div className="indicator" key={index}>
                      <div className="indicator-icon">⚠</div>

                      <div>
                        <strong>{indicator.type}</strong>
                        <p>{indicator.message}</p>

                        <div className="matches">
                          {indicator.matches.map((match, matchIndex) => (
                            <span key={matchIndex}>{match}</span>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="recommendation">
              <div className="recommendation-icon">💡</div>

              <div>
                <strong>Safety Recommendation</strong>
                <p>{result.recommendation}</p>
              </div>
            </div>
          </section>
        )}

        {result?.error && (
          <div className="error-box">
            ⚠️ {result.error}
          </div>
        )}

        <section className="how-section">
          <div className="section-heading">
            <span className="section-label">HOW IT WORKS</span>
            <h2>Three layers of protection</h2>
            <p>
              PhishGuard combines machine learning with explainable security
              indicators.
            </p>
          </div>

          <div className="feature-grid">
            <div className="feature-card">
              <div className="feature-number">01</div>
              <h3>Text Analysis</h3>
              <p>
                The email is converted into numerical features using TF-IDF
                natural language processing.
              </p>
            </div>

            <div className="feature-card">
              <div className="feature-number">02</div>
              <h3>ML Detection</h3>
              <p>
                A Multinomial Naive Bayes classifier analyzes the email for
                phishing-related patterns.
              </p>
            </div>

            <div className="feature-card">
              <div className="feature-number">03</div>
              <h3>Risk Explanation</h3>
              <p>
                Rule-based analysis identifies indicators such as urgency,
                credential requests and suspicious links.
              </p>
            </div>
          </div>
        </section>

        <section className="about-section">
          <div>
            <span className="section-label">ABOUT PHISHGUARD</span>
            <h2>Security that explains itself.</h2>
          </div>

          <p>
            PhishGuard is a Machine Learning based phishing email detection
            prototype designed to help users identify suspicious messages
            before interacting with them. The system provides a risk score and
            explains the indicators that contributed to the result.
          </p>
        </section>
      </main>

      <footer>
        <strong>PhishGuard</strong>
        <span>AI-Powered Phishing Email Detection</span>
      </footer>
    </div>
  );
}

export default App;