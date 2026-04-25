/**
 * Weighted Multi-Source Risk Scoring Algorithm v3.0
 *
 * SOURCES & BASE WEIGHTS (when all 4 available):
 *   VirusTotal     40%  — gold standard: AV engine consensus
 *   MobSF Static   25%  — code-level: permissions, APIs, manifest
 *   MobSF Dynamic  28%  — runtime: network, trackers, TLS
 *   ML Prediction   7%  — trained malware probability model
 *
 * SCORE SCALE  0–100
 *   0–29   SAFE       |  30–54  SUSPICIOUS  |  55–100  MALICIOUS
 *
 * CONFIDENCE: 25% per available source (max 100% with all 4).
 * Missing sources have their weight redistributed proportionally.
 */

// ── helpers ──────────────────────────────────────────────────────────────────
function linearMap(v, inMin, inMax, outMin, outMax) {
  if (inMax === inMin) return outMin;
  return outMin + (Math.min(Math.max(v, inMin), inMax) - inMin) / (inMax - inMin) * (outMax - outMin);
}

function redistributeWeights(base, available) {
  let activeSum = 0;
  for (const [k, w] of Object.entries(base)) { if (available[k]) activeSum += w; }
  if (activeSum === 0) return base;
  const out = {};
  for (const [k, w] of Object.entries(base)) { out[k] = available[k] ? w / activeSum : 0; }
  return out;
}

function statusFromScore(s) {
  return s < 30 ? 'SAFE' : s < 55 ? 'SUSPICIOUS' : 'MALICIOUS';
}

function calculateWeightedRiskScore(app) {
  const BASE_WEIGHTS = { vt: 0.40, mobsfStatic: 0.25, mobsfDynamic: 0.28, ml: 0.07 };

  const result = {
    vt:           { score: null, isAvailable: false, status: 'UNKNOWN', weight: 0, explanation: '', details: {} },
    mobsfStatic:  { score: null, isAvailable: false, status: 'UNKNOWN', weight: 0, explanation: '', details: {} },
    mobsfDynamic: { score: null, isAvailable: false, status: 'UNKNOWN', weight: 0, explanation: '', details: {} },
    ml:           { score: null, isAvailable: false, status: 'UNKNOWN', weight: 0, explanation: '', details: {} },
    dataSourcesCount: 0,
    confidence: 0,
    finalScore: 50,
    finalStatus: 'UNKNOWN',
    finalExplanation: '',
    breakdown: {},
    riskFactors: [],
    positiveFactors: []
  };

  // ══════════════════════════════════════════════════════════════
  // 1. VIRUSTOTAL  (base weight 40%)
  //    Detection rate → risk curve designed for APK analysis
  //    0 detections → 8 | 1-2 → 35-50 | 3-5 → 55-65
  //    6-10 / ≥10% → 65-78 | >10 / ≥20% → 78-96
  // ══════════════════════════════════════════════════════════════
  if (app.virusTotalAnalysis) {
    const vt = app.virusTotalAnalysis;
    let malCount = vt.maliciousCount || 0;
    let suspCount = vt.suspiciousCount || 0;
    let totalEngines = vt.totalEngines || 0;
    let detectedCount = malCount + suspCount;

    if (totalEngines === 0 && vt.detectionRatio && typeof vt.detectionRatio === 'string') {
      const parts = vt.detectionRatio.split('/');
      detectedCount = parseInt(parts[0]) || 0;
      totalEngines  = parseInt(parts[1]) || 1;
      malCount = detectedCount;
    }
    if (totalEngines === 0 && vt.detectedEngines !== undefined) {
      detectedCount = vt.detectedEngines;
      totalEngines  = vt.totalEngines || (detectedCount + (vt.undetectedCount || 0));
    }

    if (totalEngines > 0) {
      const rate = detectedCount / totalEngines;
      let vtScore;
      if (detectedCount === 0)      vtScore = 8;
      else if (detectedCount === 1) vtScore = 38;
      else if (detectedCount === 2) vtScore = 50;
      else if (detectedCount <= 5 || rate < 0.10) vtScore = linearMap(detectedCount, 3, 5, 55, 65);
      else if (detectedCount <= 10 || rate < 0.20) vtScore = linearMap(detectedCount, 6, 10, 65, 78);
      else vtScore = Math.min(78 + (rate - 0.20) * 90, 96);

      vtScore = Math.round(Math.min(Math.max(vtScore, 5), 96));
      result.vt.score = vtScore;
      result.vt.isAvailable = true;
      result.vt.status = statusFromScore(vtScore);
      result.vt.details = { detectedCount, totalEngines, maliciousCount: malCount, suspiciousCount: suspCount, detectionRate: `${(rate*100).toFixed(1)}%` };
      result.vt.explanation = detectedCount === 0
        ? `All ${totalEngines} AV engines reported clean.`
        : `${detectedCount}/${totalEngines} engines flagged (${(rate*100).toFixed(1)}%): ${malCount} malicious, ${suspCount} suspicious.`;

      if (detectedCount === 0) result.positiveFactors.push(`✓ ${totalEngines} AV engines found no threats`);
      if (detectedCount >= 3)  result.riskFactors.push(`⚠ ${detectedCount}/${totalEngines} AV engines detected threat (${(rate*100).toFixed(1)}%)`);
      result.dataSourcesCount++;
    }
  }

  // ══════════════════════════════════════════════════════════════
  // 2. MOBSF STATIC ANALYSIS  (base weight 25%)
  //    risk = (100 - security_score)
  //         + penalty for high-risk findings (+3 each, cap 25)
  //         + penalty for dangerous permissions (tiered)
  // ══════════════════════════════════════════════════════════════
  if (app.mobsfAnalysis) {
    const ms = app.mobsfAnalysis;
    const secScore = typeof ms.security_score === 'number' ? ms.security_score : 50;
    const highRisk = ms.high_risk_findings || 0;
    const dangerousPerms = Array.isArray(ms.dangerous_permissions) ? ms.dangerous_permissions.length : 0;

    let staticScore = Math.max(100 - secScore, 5);
    staticScore += Math.min(highRisk * 3, 25);

    if (dangerousPerms > 0) {
      const permPenalty = dangerousPerms <= 3 ? dangerousPerms * 4
        : dangerousPerms <= 7 ? 12 + (dangerousPerms - 3) * 5
        : 32 + Math.min((dangerousPerms - 7) * 2, 10);
      staticScore += permPenalty;
    }
    staticScore = Math.round(Math.min(Math.max(staticScore, 5), 96));

    result.mobsfStatic.score = staticScore;
    result.mobsfStatic.isAvailable = true;
    result.mobsfStatic.status = statusFromScore(staticScore);
    result.mobsfStatic.details = { securityScore: secScore, highRiskFindings: highRisk, dangerousPermissions: dangerousPerms };
    result.mobsfStatic.explanation = `MobSF score ${secScore}/100 → base risk ${100-secScore}. `
      + `${highRisk} high-risk finding(s), ${dangerousPerms} dangerous permission(s) → final ${staticScore}.`;

    if (secScore >= 70 && highRisk === 0) result.positiveFactors.push(`✓ MobSF static score ${secScore}/100 — low code-level risk`);
    if (highRisk > 0)        result.riskFactors.push(`⚠ ${highRisk} high-risk static code finding(s)`);
    if (dangerousPerms >= 5) result.riskFactors.push(`⚠ ${dangerousPerms} dangerous Android permissions requested`);
    result.dataSourcesCount++;
  }

  // ══════════════════════════════════════════════════════════════
  // 3. MOBSF DYNAMIC ANALYSIS  (base weight 28%)
  //    Base 10 + additive penalties:
  //      manifest issues, network config, trackers,
  //      network security issues, open redirects, excessive domains
  // ══════════════════════════════════════════════════════════════
  const hasMobsfDynamic   = !!(app.mobsfAnalysis?.dynamic_analysis);
  const hasRuntimeDynamic = !!(app.dynamicAnalysis?.status === 'completed');

  if (hasMobsfDynamic || hasRuntimeDynamic) {
    const dyn     = hasMobsfDynamic   ? app.mobsfAnalysis.dynamic_analysis : {};
    const runtime = hasRuntimeDynamic ? app.dynamicAnalysis : {};

    const highManifest = dyn.high_manifest_issues  || 0;
    const warnManifest = dyn.warn_manifest_issues  || 0;
    const highNet      = dyn.high_network_issues   || 0;
    const trackers     = runtime.trackers               || 0;
    const netIssues    = runtime.network_security_issues || 0;
    const openRedirects= runtime.open_redirects          || 0;
    const domains      = runtime.domains_count           || 0;

    const manifestPenalty  = Math.min(highManifest * 10 + warnManifest * 3, 35);
    const netConfigPenalty = Math.min(highNet * 12, 30);
    const trackerPenalty   = Math.min(trackers    * 8,  24);
    const netIssuePenalty  = Math.min(netIssues   * 14, 28);
    const redirectPenalty  = Math.min(openRedirects * 10, 20);
    const domainPenalty    = domains > 20 ? 5 : 0;

    const dynScore = Math.round(Math.min(Math.max(
      10 + manifestPenalty + netConfigPenalty + trackerPenalty + netIssuePenalty + redirectPenalty + domainPenalty,
      5), 96));

    result.mobsfDynamic.score = dynScore;
    result.mobsfDynamic.isAvailable = true;
    result.mobsfDynamic.status = statusFromScore(dynScore);
    result.mobsfDynamic.details = {
      highManifestIssues: highManifest, warnManifestIssues: warnManifest,
      highNetworkConfigIssues: highNet, trackers, networkSecurityIssues: netIssues,
      openRedirects, domains,
      penaltyBreakdown: { manifestPenalty, netConfigPenalty, trackerPenalty, netIssuePenalty, redirectPenalty, domainPenalty }
    };
    result.mobsfDynamic.explanation = `Base 10 + manifest(+${manifestPenalty}) + netConfig(+${netConfigPenalty}) + trackers(+${trackerPenalty}) + netSec(+${netIssuePenalty}) + redirects(+${redirectPenalty}) + domains(+${domainPenalty}) = ${dynScore}.`;

    if (trackers === 0 && netIssues === 0) result.positiveFactors.push(`✓ No trackers or network security issues at runtime`);
    if (trackers > 0)      result.riskFactors.push(`⚠ ${trackers} advertising/analytics tracker(s) detected at runtime`);
    if (netIssues > 0)     result.riskFactors.push(`⚠ ${netIssues} network security issue(s) (e.g. cleartext traffic)`);
    if (openRedirects > 0) result.riskFactors.push(`⚠ ${openRedirects} open redirect(s) detected`);
    if (highManifest > 0)  result.riskFactors.push(`⚠ ${highManifest} high-severity manifest issue(s)`);
    result.dataSourcesCount++;
  }

  // ══════════════════════════════════════════════════════════════
  // 4. ML PREDICTION  (base weight 7%)
  //    Probability 0-1 → risk score 8-96
  //    <0.25 SAFE | 0.25-0.60 SUSPICIOUS | >0.60 MALICIOUS
  // ══════════════════════════════════════════════════════════════
  if (app.mlPredictionScore != null) {
    const mlProb = parseFloat(app.mlPredictionScore);
    if (!isNaN(mlProb) && mlProb >= 0 && mlProb <= 1) {
      const mlScore = Math.round(linearMap(mlProb, 0, 1, 8, 96));
      result.ml.score = mlScore;
      result.ml.isAvailable = true;
      result.ml.status = mlProb < 0.25 ? 'SAFE' : mlProb < 0.60 ? 'SUSPICIOUS' : 'MALICIOUS';
      result.ml.details = { probability: mlProb, label: app.mlPredictionLabel || '—' };
      result.ml.explanation = `ML maliciousness probability: ${(mlProb*100).toFixed(1)}% → risk score ${mlScore}.`;
      if (mlProb < 0.25) result.positiveFactors.push(`✓ ML model: low maliciousness probability (${(mlProb*100).toFixed(1)}%)`);
      if (mlProb > 0.60) result.riskFactors.push(`⚠ ML model: high maliciousness probability (${(mlProb*100).toFixed(1)}%)`);
      result.dataSourcesCount++;
    }
  }

  // ══════════════════════════════════════════════════════════════
  // WEIGHT REDISTRIBUTION & FINAL SCORE
  // ══════════════════════════════════════════════════════════════
  if (result.dataSourcesCount === 0) {
    result.finalScore = 50; result.finalStatus = 'UNKNOWN'; result.confidence = 0;
    result.finalExplanation = 'No analysis data available.';
    return result;
  }

  const available = {
    vt: result.vt.isAvailable, mobsfStatic: result.mobsfStatic.isAvailable,
    mobsfDynamic: result.mobsfDynamic.isAvailable, ml: result.ml.isAvailable,
  };
  const weights = redistributeWeights(BASE_WEIGHTS, available);
  result.vt.weight = weights.vt;
  result.mobsfStatic.weight = weights.mobsfStatic;
  result.mobsfDynamic.weight = weights.mobsfDynamic;
  result.ml.weight = weights.ml;

  let weightedSum = 0;
  if (result.vt.isAvailable)          weightedSum += result.vt.score          * weights.vt;
  if (result.mobsfStatic.isAvailable) weightedSum += result.mobsfStatic.score  * weights.mobsfStatic;
  if (result.mobsfDynamic.isAvailable)weightedSum += result.mobsfDynamic.score * weights.mobsfDynamic;
  if (result.ml.isAvailable)          weightedSum += result.ml.score           * weights.ml;

  result.finalScore  = Math.round(Math.min(Math.max(weightedSum, 5), 96) * 10) / 10;
  result.finalStatus = statusFromScore(result.finalScore);
  result.confidence  = Math.round((result.dataSourcesCount / 4) * 100);

  const sourceStr = `${result.dataSourcesCount}/4 sources`;
  result.finalExplanation = result.finalStatus === 'MALICIOUS'
    ? `Risk score ${result.finalScore}/100 based on ${sourceStr}. This APK exhibits characteristics consistent with malware — immediate review recommended.`
    : result.finalStatus === 'SUSPICIOUS'
    ? `Risk score ${result.finalScore}/100 based on ${sourceStr}. Suspicious behaviour detected — manual inspection recommended before allowing on devices.`
    : `Risk score ${result.finalScore}/100 based on ${sourceStr}. No significant threats identified across available analysis sources.`;

  result.breakdown = {
    sources: {
      virustotal:   result.vt.isAvailable          ? result.vt.score          : null,
      mobsfStatic:  result.mobsfStatic.isAvailable  ? result.mobsfStatic.score  : null,
      mobsfDynamic: result.mobsfDynamic.isAvailable ? result.mobsfDynamic.score : null,
      ml:           result.ml.isAvailable           ? result.ml.score           : null,
    },
    weights: {
      virustotal:   weights.vt,
      mobsfStatic:  weights.mobsfStatic,
      mobsfDynamic: weights.mobsfDynamic,
      ml:           weights.ml,
    },
    explanations: {
      virustotal:   result.vt.explanation,
      mobsfStatic:  result.mobsfStatic.explanation,
      mobsfDynamic: result.mobsfDynamic.explanation,
      ml:           result.ml.explanation,
    },
    details: {
      virustotal:   result.vt.details,
      mobsfStatic:  result.mobsfStatic.details,
      mobsfDynamic: result.mobsfDynamic.details,
      ml:           result.ml.details,
    }
  };

  return result;
}

/**
 * Legacy alias kept for backward compatibility
 */
function Map(value, inMin, inMax, outMin, outMax) {
  return linearMap(value, inMin, inMax, outMin, outMax);
}

module.exports = { calculateWeightedRiskScore, Map, linearMap };
