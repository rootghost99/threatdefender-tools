// Entry point for Azure Functions
// This file imports all function definitions
// Wrap requires in try-catch to debug loading errors

console.log('========================================');
console.log('Starting Azure Functions initialization');
console.log('Node version:', process.version);
console.log('========================================');
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
  require('./LoadingDiagnostic');
  console.log('✓ LoadingDiagnostic loaded');
} catch (e) {
  console.error('✗ LoadingDiagnostic failed:', e.message);
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

try {
  require('./test-simple');
  console.log('✓ test-simple loaded');
} catch (e) {
  console.error('✗ test-simple failed:', e.message);
}

try {
  require('./DiagnosticEndpoint');
  console.log('✓ DiagnosticEndpoint loaded');
} catch (e) {
  console.error('✗ DiagnosticEndpoint failed:', e.message, e.stack);
}

try {
  require('./PromptsMinimal');
  console.log('✓ PromptsMinimal loaded');
} catch (e) {
  console.error('✗ PromptsMinimal failed:', e.message, e.stack);
}

console.log('========================================');
console.log('All Azure Functions modules loaded');
console.log('Total modules in cache:', Object.keys(require.cache).length);
console.log('========================================');
