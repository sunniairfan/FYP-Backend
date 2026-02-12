/**
 * Enhanced Weighted Multi-Source Risk Scoring Algorithm v2.0
 * Aggregates VT, MobSF Static, MobSF Dynamic+Permissions, and ML predictions with:
 * - Permissions logic integrated into MobSF dynamic score
 * - Dynamic weight adjustment based on data availability
 * - Graceful handling of missing data with intelligent defaults
 * - Confidence scoring based on data completeness
 */

function calculateWeightedRiskScore(app) {
  // Initialize base scores and confidence tracking
  const scores = {
    vt: { score: null, isAvailable: false, status: 'unknown', details: {} },
    mobsfStatic: { score: null, isAvailable: false, status: 'unknown', details: {} },
    mobsfDynamic: { score: null, isAvailable: false, status: 'unknown', details: {} },
    ml: { score: null, isAvailable: false, status: 'unknown', details: {} },
    dataSourcesCount: 0,
    confidence: 0,
    finalScore: 0,
    finalStatus: 'UNKNOWN',
    breakdown: {}
  };

  // ============================================
  // 1. VT MULTI-ENGINE SCANNING
  // ============================================
  if (app.virusTotalAnalysis) {
    const vt = app.virusTotalAnalysis;
    let detectedEngines = 0;
    let totalEngines = 0;
    
    // Parse detection ratio (e.g., "2/65" -> detected=2, total=65)
    if (vt.detectionRatio && typeof vt.detectionRatio === 'string') {
      const parts = vt.detectionRatio.split('/');
      detectedEngines = parseInt(parts[0]) || 0;
      totalEngines = parseInt(parts[1]) || 1;
    } else if (vt.maliciousCount !== undefined && vt.suspiciousCount !== undefined) {
      detectedEngines = (vt.maliciousCount || 0) + (vt.suspiciousCount || 0);
      totalEngines = (vt.maliciousCount || 0) + (vt.suspiciousCount || 0) + (vt.undetectedCount || 0);
    } else if (vt.detectedEngines !== undefined && vt.totalEngines !== undefined) {
      detectedEngines = vt.detectedEngines;
      totalEngines = vt.totalEngines;
    }

    // Calculate VT score with smooth gradient
    if (totalEngines > 0) {
      const detectionPercentage = (detectedEngines / totalEngines) * 100;
      
      // Smooth gradient: maps 0-100% to 10-95 score
      scores.vt.score = 10 + (detectionPercentage * 0.85);
      scores.vt.score = Math.min(Math.max(scores.vt.score, 10), 95);
      scores.vt.isAvailable = true;
      scores.dataSourcesCount++;

      // Status mapping
      if (detectionPercentage === 0) {
        scores.vt.status = 'SAFE';
      } else if (detectionPercentage < 10) {
        scores.vt.status = 'RISKY';
      } else if (detectionPercentage < 30) {
        scores.vt.status = 'SUSPICIOUS';
      } else {
        scores.vt.status = 'MALICIOUS';
      }
    } else {
      // No scan data available - use neutral default
      scores.vt.score = 50; // Neutral middle ground
      scores.vt.isAvailable = false;
      scores.vt.status = 'UNKNOWN';
    }
  } else {
    // VirusTotal data completely unavailable - use neutral default
    scores.vt.score = 50;
    scores.vt.isAvailable = false;
  }

  // ============================================
  // 2. MOBSF STATIC ANALYSIS
  // ============================================
  if (app.mobsfAnalysis) {
    const mobsf = app.mobsfAnalysis;
    const securityScore = mobsf.security_score || 50; // Default to medium if missing
    const highRiskFindings = mobsf.high_risk_findings || 0;

    // Enhanced scoring: combine security score with findings
    // Security score: 0-100 (lower = riskier)
    // High risk findings: each adds to risk
    let mobsfScore = 0;

    if (securityScore >= 70) {
      // Low risk: high security score
      mobsfScore = Map(securityScore, 70, 100, 15, 25) - Math.min(highRiskFindings * 3, 20);
      scores.mobsfStatic.status = 'SAFE';
    } else if (securityScore >= 50) {
      // Medium-low risk
      mobsfScore = Map(securityScore, 50, 70, 35, 55) + Math.min(highRiskFindings * 2, 15);
      scores.mobsfStatic.status = 'SUSPICIOUS';
    } else if (securityScore >= 30) {
      // Medium-high risk
      mobsfScore = Map(securityScore, 30, 50, 55, 75) + Math.min(highRiskFindings * 2, 20);
      scores.mobsfStatic.status = 'SUSPICIOUS';
    } else {
      // High risk: low security score
      mobsfScore = Map(securityScore, 0, 30, 75, 95) + Math.min(highRiskFindings * 2, 20);
      scores.mobsfStatic.status = 'MALICIOUS';
    }

    // Cap the score
    scores.mobsfStatic.score = Math.min(Math.max(mobsfScore, 10), 95);
    scores.mobsfStatic.isAvailable = true;
    scores.mobsfStatic.details = {
      securityScore: securityScore,
      highRiskFindings: highRiskFindings
    };
    scores.dataSourcesCount++;
  } else {
    // MobSF data unavailable
    scores.mobsfStatic.score = 50; // Neutral default
    scores.mobsfStatic.isAvailable = false;
  }

  // ============================================
  // 2.5 MOBSF DYNAMIC ANALYSIS + PERMISSIONS
  // ============================================
  // Dynamic analysis combined with dangerous permissions assessment
  let mobsfDynamicScore = null;
  let mobsfDynamicStatus = 'UNKNOWN';
  let dynamicDetails = { available: false, permissionCount: 0, permissionScore: 0 };

  // First, calculate permissions risk score if available
  let permissionRiskScore = 40; // Default neutral
  let permissionCount = 0;
  
  if (app.mobsfAnalysis && app.mobsfAnalysis.dangerous_permissions) {
    permissionCount = Array.isArray(app.mobsfAnalysis.dangerous_permissions)
      ? app.mobsfAnalysis.dangerous_permissions.length
      : 0;
    
    dynamicDetails.permissionCount = permissionCount;
    
    // Permissions risk mapping: 0 = 10 (safe), 10+ = 95 (malicious)
    if (permissionCount === 0) {
      permissionRiskScore = 10;
    } else if (permissionCount <= 3) {
      permissionRiskScore = 20 + (permissionCount * 5);
    } else if (permissionCount <= 6) {
      permissionRiskScore = 35 + (permissionCount * 8);
    } else if (permissionCount <= 10) {
      permissionRiskScore = 60 + (permissionCount * 3);
    } else {
      // 10+ dangerous permissions
      permissionRiskScore = 75 + Math.min((permissionCount - 10) * 2, 20);
    }
    permissionRiskScore = Math.min(Math.max(permissionRiskScore, 10), 95);
  }
  
  dynamicDetails.permissionScore = permissionRiskScore;

  // Now combine dynamic analysis with permissions
  if (app.mobsfAnalysis && app.mobsfAnalysis.dynamic_analysis) {
    // Dynamic analysis exists - combine with permissions
    const baseDynamicScore = 40; // Neutral base for dynamic
    
    // Weight the combination: 60% permissions, 40% dynamic baseline
    mobsfDynamicScore = (permissionRiskScore * 0.6) + (baseDynamicScore * 0.4);
    mobsfDynamicScore = Math.min(Math.max(mobsfDynamicScore, 10), 95);
    
    dynamicDetails.available = true;
    
    if (mobsfDynamicScore < 35) {
      mobsfDynamicStatus = 'SAFE';
    } else if (mobsfDynamicScore < 60) {
      mobsfDynamicStatus = 'SUSPICIOUS';
    } else {
      mobsfDynamicStatus = 'MALICIOUS';
    }
    
    scores.mobsfDynamic.isAvailable = true;
    scores.mobsfDynamic.score = mobsfDynamicScore;
    scores.mobsfDynamic.status = mobsfDynamicStatus;
    scores.mobsfDynamic.details = dynamicDetails;
    scores.dataSourcesCount++;
  } else {
    // No dynamic analysis available
    // Permissions are already factored into MobSF Static scoring during analysis
    // Don't count as a separate source
    scores.mobsfDynamic.isAvailable = false;
    scores.mobsfDynamic.score = 40; // Neutral default
    scores.mobsfDynamic.status = 'UNKNOWN';
    scores.mobsfDynamic.details = dynamicDetails;
  }

  // ============================================
  // 4. ML PREDICTION
  // ============================================
  if (app.mlPredictionScore !== undefined && app.mlPredictionScore !== null) {
    const mlScore = parseFloat(app.mlPredictionScore);
    
    if (!isNaN(mlScore) && mlScore >= 0 && mlScore <= 1) {
      // Convert 0-1 scale to 0-100 risk scale with smooth gradient
      scores.ml.score = 10 + (mlScore * 85);
      scores.ml.score = Math.min(Math.max(scores.ml.score, 10), 95);
      scores.ml.isAvailable = true;
      scores.dataSourcesCount++;

      // Status mapping
      if (mlScore < 0.3) {
        scores.ml.status = 'SAFE';
      } else if (mlScore < 0.6) {
        scores.ml.status = 'SUSPICIOUS';
      } else {
        scores.ml.status = 'MALICIOUS';
      }
    } else {
      // Invalid ML score
      scores.ml.score = 50;
      scores.ml.isAvailable = false;
    }
  } else {
    // ML data unavailable
    scores.ml.score = 50;
    scores.ml.isAvailable = false;
  }

  // ============================================
  // DYNAMIC WEIGHT ADJUSTMENT
  // Redistribute weights based on available data sources
  // 4 sources: VT (30%), MobSF Static (25%), MobSF Dynamic+Perm (20%), ML (25%)
  // ============================================
  const weightConfig = {
    allAvailable: { vt: 0.30, mobsfStatic: 0.25, mobsfDynamic: 0.20, ml: 0.25 },
    noML: { vt: 0.35, mobsfStatic: 0.30, mobsfDynamic: 0.35, ml: 0 },
    noVT: { vt: 0, mobsfStatic: 0.35, mobsfDynamic: 0.30, ml: 0.35 },
    noMobSFD: { vt: 0.40, mobsfStatic: 0.35, mobsfDynamic: 0, ml: 0.25 },
  };

  let weights = weightConfig.allAvailable;

  // Determine which weight configuration to use
  if (scores.dataSourcesCount === 0) {
    // No data available - use conservative defaults
    scores.finalScore = 50;
    scores.finalStatus = 'UNKNOWN';
    scores.confidence = 0;
    return scores;
  }

  // Adjust weights based on available sources
  if (!scores.ml.isAvailable) {
    weights = weightConfig.noML;
  } else if (!scores.vt.isAvailable) {
    weights = weightConfig.noVT;
  } else if (!scores.mobsfDynamic.isAvailable) {
    weights = weightConfig.noMobSFD;
  }

  // ============================================
  // CALCULATE FINAL WEIGHTED SCORE
  // ============================================
  let weightedSum = 0;
  let totalWeight = 0;

  if (scores.vt.isAvailable) {
    weightedSum += scores.vt.score * weights.vt;
    totalWeight += weights.vt;
  }
  if (scores.mobsfStatic.isAvailable) {
    weightedSum += scores.mobsfStatic.score * weights.mobsfStatic;
    totalWeight += weights.mobsfStatic;
  }
  if (scores.mobsfDynamic.isAvailable) {
    weightedSum += scores.mobsfDynamic.score * weights.mobsfDynamic;
    totalWeight += weights.mobsfDynamic;
  }
  if (scores.ml.isAvailable) {
    weightedSum += scores.ml.score * weights.ml;
    totalWeight += weights.ml;
  }

  // Normalize final score
  scores.finalScore = totalWeight > 0 ? Math.round((weightedSum / totalWeight) * 100) / 100 : 50;
  scores.finalScore = Math.min(Math.max(scores.finalScore, 10), 95);

  // ============================================
  // CONFIDENCE SCORING (0-100%)
  // Higher confidence = more data sources available (4 sources max)
  // ============================================
  scores.confidence = Math.round((scores.dataSourcesCount / 4) * 100);

  // ============================================
  // CLASSIFY APP STATUS with refined thresholds
  // ============================================
  if (scores.finalScore < 35) {
    scores.finalStatus = 'SAFE';
  } else if (scores.finalScore < 60) {
    scores.finalStatus = 'SUSPICIOUS';
  } else {
    scores.finalStatus = 'MALICIOUS';
  }

  // Store breakdown for transparency
  scores.breakdown = {
    sources: {
      virustotal: scores.vt.isAvailable ? scores.vt.score : null,
      mobsfStatic: scores.mobsfStatic.isAvailable ? scores.mobsfStatic.score : null,
      mobsfDynamic: scores.mobsfDynamic.isAvailable ? scores.mobsfDynamic.score : null,
      ml: scores.ml.isAvailable ? scores.ml.score : null,
    },
    sourceDetails: {
      virustotal: scores.vt.details,
      mobsfStatic: scores.mobsfStatic.details,
      mobsfDynamic: scores.mobsfDynamic.details,
      ml: scores.ml.details,
    },
    weights: {
      virustotal: weights.vt,
      mobsfStatic: weights.mobsfStatic,
      mobsfDynamic: weights.mobsfDynamic,
      ml: weights.ml,
    }
  };

  return scores;
}

/**
 * Helper function: Linear mapping function
 * Maps value from [inMin, inMax] range to [outMin, outMax] range
 */
function Map(value, inMin, inMax, outMin, outMax) {
  return outMin + (value - inMin) * (outMax - outMin) / (inMax - inMin);
}

module.exports = { calculateWeightedRiskScore, Map };
