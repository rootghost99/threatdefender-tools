# Crypto Error Fix Documentation

## Problem
When running prompts from the Prompt Gallery, users encountered the error:
```
Error: crypto is not defined
```

## Root Cause
The `@azure/openai` SDK (and other Azure SDKs) depend on Node.js's built-in `crypto` module. In Azure Functions deployments, bundlers or certain runtime configurations can prevent the crypto module from being properly loaded, causing "crypto is not defined" errors.

## Solution Pattern
**Replace Azure SDK calls with direct REST API calls using axios.**

This is the proven pattern already used successfully in `KQLAnalyzer.js`.

## Specific Fix Applied

### File: `api/PromptsAPI-REST.js`

#### Changes Made:
1. **Removed SDK imports:**
   ```javascript
   // REMOVED:
   const { OpenAIClient, AzureKeyCredential } = require('@azure/openai');
   ```

2. **Removed SDK client initialization function:**
   ```javascript
   // REMOVED: getOpenAIClient() function entirely
   ```

3. **Replaced SDK call with REST API in `runPrompt()` function (lines 641-687):**

   **Before (using SDK):**
   ```javascript
   const openAI = getOpenAIClient();
   const result = await openAI.getChatCompletions(deployment, messages, {
     temperature,
     maxTokens
   });
   ```

   **After (using REST API):**
   ```javascript
   // Call Azure OpenAI using REST API directly (avoids SDK crypto issues)
   const endpoint = process.env.AZURE_OPENAI_ENDPOINT;
   const apiKey = process.env.AZURE_OPENAI_API_KEY;
   const deployment = process.env.AZURE_OPENAI_DEPLOYMENT || 'gpt-4';

   // Use REST API directly instead of SDK to avoid crypto issues
   const apiVersion = '2024-02-01';
   const url = `${endpoint}/openai/deployments/${deployment}/chat/completions?api-version=${apiVersion}`;

   const openAIResponse = await axios({
     method: 'POST',
     url: url,
     headers: {
       'api-key': apiKey,
       'Content-Type': 'application/json'
     },
     data: {
       messages: messages,
       max_tokens: maxTokens,
       temperature: temperature
     },
     timeout: 60000,
     validateStatus: () => true
   });

   if (openAIResponse.status !== 200) {
     context.error('OpenAI API error:', openAIResponse.data);
     throw new Error(`Azure OpenAI API call failed: ${openAIResponse.data?.error?.message || openAIResponse.status}`);
   }

   const result = openAIResponse.data;
   ```

## What NOT to Do

### ❌ DO NOT try to replace `@azure/data-tables` SDK with REST API
- The table storage operations use `crypto` for SAS token generation, which works fine in Azure Functions
- Attempting to use `@azure/data-tables` SDK instead breaks the application with:
  - "failed to execute json on response: unexpected end of json input" errors
  - 404 errors when viewing prompt gallery
  - The manual REST API implementation with crypto-based SAS tokens is the correct approach

### ❌ DO NOT remove crypto module from table storage operations
- The `crypto` require statement is needed for Azure Table Storage SAS token generation
- This usage works correctly in production
- Only the OpenAI SDK needs to be replaced with REST API

## Key Principles

1. **For OpenAI calls:** Use REST API with axios (no SDK)
2. **For Table Storage:** Keep using manual REST API with crypto-based SAS tokens (current implementation)
3. **Pattern to follow:** See `api/KQLAnalyzer.js` lines 101-122 for reference implementation

## Testing Checklist
After applying crypto fixes, verify:
- ✅ Prompt gallery listing works (GET /api/prompts)
- ✅ Prompt creation works (POST /api/prompts)
- ✅ Prompt viewing works (GET /api/prompts/{id})
- ✅ Prompt execution works (POST /api/prompts/{id}/run) - NO CRYPTO ERROR
- ✅ Prompt editing works (PUT /api/prompts/{id})
- ✅ Prompt deletion works (DELETE /api/prompts/{id})

## Git Commits
- Fix commit: `faa72b3` - "Fix crypto error in prompt execution by using OpenAI REST API"
- Revert of failed approach: `950b5d5` - Reverted attempted @azure/data-tables SDK replacement

## Reference Files
- Working example: `api/KQLAnalyzer.js` (lines 101-122)
- Fixed file: `api/PromptsAPI-REST.js` (lines 641-687)
