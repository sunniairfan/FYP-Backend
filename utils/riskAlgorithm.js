/**
 * Weighted Multi-Source Risk Scoring Algorithm
 * Aggregates ML prediction, MobSF analysis, and VT multi-engine scanning
 */

function calculateWeightedRiskScore(app) {
  // Initialize scores object
  const scores = {
    vt: { score: 0, weight: 0.5, status: 'unknown' },
    mobsf: { score: 0, weight: 0.3, status: 'unknown' },
    ml: { score: 0, weight: 0.2, status: 'unknown' },
    finalScore: 0,
    finalStatus: 'UNKNOWN',
  };

  // ============================================
  // 1. VT MULTI-ENGINE SCANNING (Weight: 50%)
  // ============================================
  if (app.virusTotalAnalysis) {
    const vt = app.virusTotalAnalysis;
    
    // Parse detection ratio (e.g., "2/65" -> detected=2, total=65)
    let detectedEngines = 0;
    let totalEngines = 0;
    
    if (vt.detectionRatio && typeof vt.detectionRatio === 'string') {
      const parts = vt.detectionRatio.split('/');
      detectedEngines = parseInt(parts[0]) || 0;
      totalEngines = parseInt(parts[1]) || 1;
    } else if (vt.maliciousCount !== undefined && vt.suspiciousCount !== undefined) {
      detectedEngines = (vt.maliciousCount || 0) + (vt.suspiciousCount || 0);
      totalEngines = (vt.maliciousCount || 0) + (vt.suspiciousCount || 0) + (vt.undetectedCount || 0);
    }

    // Calculate VT score based on detection ratio
    if (totalEngines > 0) {
      const detectionPercentage = (detectedEngines / totalEngines) * 100;
      
      if (detectionPercentage === 0) {
        // 0 engines detected = Safe (score: 10)
        scores.vt.score = 10;
        scores.vt.status = 'SAFE';
      } else if (detectionPercentage <= 5) {
        // 1-5% detected = Low Risk (score: 30)
        scores.vt.score = 30;
        scores.vt.status = 'RISKY';
      } else if (detectionPercentage <= 20) {
        // 5-20% detected = Medium Risk (score: 50)
        scores.vt.score = 50;
        scores.vt.status = 'SUSPICIOUS';
      } else if (detectionPercentage <= 50) {
        // 20-50% detected = High Risk (score: 75)
        scores.vt.score = 75;
        scores.vt.status = 'MALICIOUS';
      } else {
        // 50%+ detected = Very High Risk (score: 95)
        scores.vt.score = 95;
        scores.vt.status = 'MALICIOUS';
      }
    } else {
      // No engines = unknown
      scores.vt.score = 50;
      scores.vt.status = 'UNKNOWN';
    }
  }

  // ============================================
  // 2. MOBSF STATIC ANALYSIS (Weight: 30%)
  // ============================================
  if (app.mobsfAnalysis) {
    const mobsf = app.mobsfAnalysis;
    const securityScore = mobsf.security_score || 0;
    const highRiskFindings = mobsf.high_risk_findings || 0;

    // Security Score: 0-100 (lower is riskier)
    // High Risk Findings: more findings = more risk
    let mobsfScore = 0;

    if (securityScore >= 70) {
      // High security score = Low risk
      mobsfScore = 15 - (highRiskFindings * 2);
      scores.mobsf.status = 'SAFE';
    } else if (securityScore >= 40) {
      // Medium security score = Medium risk
      mobsfScore = 50 + (highRiskFindings * 1.5);
      scores.mobsf.status = 'SUSPICIOUS';
    } else {
      // Low security score = High risk
      mobsfScore = 75 + (highRiskFindings * 2);
      scores.mobsf.status = 'MALICIOUS';
    }

    // Cap the score at max 95
    scores.mobsf.score = Math.min(Math.max(mobsfScore, 0), 95);
  }

  // ============================================
  // 3. ML PREDICTION (Weight: 20%)
  // ============================================
  if (app.mlPredictionScore !== undefined && app.mlPredictionScore !== null) {
    const mlScore = app.mlPredictionScore; // 0-1 range

    // Convert 0-1 scale to 0-100 risk scale
    // 0-0.3 = Safe (score 10-20)
    // 0.3-0.6 = Suspicious (score 40-60)
    // 0.6-1.0 = Malicious (score 70-95)
    
    let mlRiskScore = mlScore * 100;

    if (mlScore < 0.3) {
      scores.ml.score = mlScore * 33 + 10; // Maps to 10-20
      scores.ml.status = 'SAFE';
    } else if (mlScore < 0.6) {
      scores.ml.score = (mlScore - 0.3) * 67 + 40; // Maps to 40-60
      scores.ml.status = 'SUSPICIOUS';
    } else {
      scores.ml.score = (mlScore - 0.6) * 87.5 + 70; // Maps to 70-95
      scores.ml.status = 'MALICIOUS';
    }

    scores.ml.score = Math.min(Math.max(scores.ml.score, 0), 95);
  }

  // ============================================
  // CALCULATE FINAL WEIGHTED SCORE
  // ============================================
  const totalWeight = scores.vt.weight + scores.mobsf.weight + scores.ml.weight;
  
  scores.finalScore = 
    (scores.vt.score * scores.vt.weight +
     scores.mobsf.score * scores.mobsf.weight +
     scores.ml.score * scores.ml.weight) / totalWeight;

  // Round to 2 decimal places
  scores.finalScore = Math.round(scores.finalScore * 100) / 100;

  // ============================================
  // CLASSIFY APP STATUS
  // ============================================
  if (scores.finalScore < 50) {
    scores.finalStatus = 'SAFE';
  } else if (scores.finalScore < 75) {
    scores.finalStatus = 'SUSPICIOUS';
  } else {
    scores.finalStatus = 'MALICIOUS';
  }

  return scores;
}

module.exports = { calculateWeightedRiskScore };
