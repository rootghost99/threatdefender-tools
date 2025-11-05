// Entry point for Azure Functions
// This file imports all function definitions
// Wrap requires in try-catch to debug loading errors
try {
  require('./IRPlaybook');
  console.log('✓ IRPlaybook loaded');
} catch (e) {
  console.error('✗ IRPlaybook failed:', e.message);
}

try {
  require('./KQLAnalyzer');
  console.log('✓ KQLAnalyzer loaded');
} catch (e) {
  console.error('✗ KQLAnalyzer failed:', e.message);
}

try {
  require('./ThreatIntelLookup');
  console.log('✓ ThreatIntelLookup loaded');
} catch (e) {
  console.error('✗ ThreatIntelLookup failed:', e.message);
}

try {
  require('./EmailPosture');
  console.log('✓ EmailPosture loaded');
} catch (e) {
  console.error('✗ EmailPosture failed:', e.message);
}

try {
  require('./HybridAnalysisLookup');
  console.log('✓ HybridAnalysisLookup loaded');
} catch (e) {
  console.error('✗ HybridAnalysisLookup failed:', e.message);
}

try {
  require('./PromptsHealthCheck');
  console.log('✓ PromptsHealthCheck loaded');
} catch (e) {
  console.error('✗ PromptsHealthCheck failed:', e.message);
}

try {
  require('./PromptsDiagnostics');
  console.log('✓ PromptsDiagnostics loaded');
} catch (e) {
  console.error('✗ PromptsDiagnostics failed:', e.message);
}

try {
  require('./PromptsAPI');
  console.log('✓ PromptsAPI loaded');
} catch (e) {
  console.error('✗ PromptsAPI failed:', e.message, e.stack);
}

try {
  require('./PromptRunAPI');
  console.log('✓ PromptRunAPI loaded');
} catch (e) {
  console.error('✗ PromptRunAPI failed:', e.message);
}

console.log('All Azure Functions modules loaded');
