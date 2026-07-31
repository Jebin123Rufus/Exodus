import dotenv from 'dotenv';
dotenv.config();

import { PHASE_2_SYSTEM_PROMPT, buildUserMessage } from '../src/evidence/evidencePrompts.js';
import Groq from 'groq-sdk';

async function runEvidenceTests() {
  console.log('==================================================');
  console.log('RUNNING SENTINELAI PHASE 2 - EVIDENCE ENGINE TEST SUITE');
  console.log('==================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`[PASS] ${message}`);
      passed++;
    } else {
      console.error(`[FAIL] ${message}`);
      failed++;
    }
  }

  // ---------------------------------------------------------
  // TEST 1: System prompt is populated and contains key sections
  // ---------------------------------------------------------
  console.log('--- Test 1: System Prompt Structure Validation ---');
  assert(typeof PHASE_2_SYSTEM_PROMPT === 'string' && PHASE_2_SYSTEM_PROMPT.length > 500,
    'System prompt is a non-empty string of sufficient length');
  assert(PHASE_2_SYSTEM_PROMPT.includes('HTTP_ENDPOINT'),
    'System prompt includes HTTP_ENDPOINT node type');
  assert(PHASE_2_SYSTEM_PROMPT.includes('DATABASE_QUERY'),
    'System prompt includes DATABASE_QUERY node type');
  assert(PHASE_2_SYSTEM_PROMPT.includes('SECRET'),
    'System prompt includes SECRET node type');
  assert(PHASE_2_SYSTEM_PROMPT.includes('AUTHENTICATION'),
    'System prompt includes AUTHENTICATION node type');
  assert(PHASE_2_SYSTEM_PROMPT.includes('FLOWS_TO'),
    'System prompt includes FLOWS_TO relationship type');
  assert(PHASE_2_SYSTEM_PROMPT.includes('Never classify vulnerabilities'),
    'System prompt contains "Never classify vulnerabilities" constraint');
  assert(PHASE_2_SYSTEM_PROMPT.includes('Only describe observable evidence'),
    'System prompt contains "Only describe observable evidence" rule');

  // ---------------------------------------------------------
  // TEST 2: User message builder produces correct prompt structure
  // ---------------------------------------------------------
  console.log('\n--- Test 2: User Message Builder ---');
  const sampleChunk = {
    filePath: 'server.js',
    language: 'javascript',
    chunkId: 'chk_abc123',
    chunkIndex: 0,
    totalChunks: 3,
    startLine: 1,
    endLine: 30,
    startOffset: 0,
    endOffset: 800,
    content: `const express = require('express');\nconst jwt = require('jsonwebtoken');\n\napp.post('/api/login', (req, res) => {\n  const { username, password } = req.body;\n  const user = db.findOne({ username });\n  if (user && user.password === password) {\n    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET);\n    res.json({ token });\n  }\n});`
  };

  const userMessage = buildUserMessage(sampleChunk);
  assert(typeof userMessage === 'string', 'User message is a valid string');
  assert(userMessage.includes('server.js'), 'User message contains correct file path');
  assert(userMessage.includes('javascript'), 'User message contains correct language');
  assert(userMessage.includes('chk_abc123'), 'User message contains chunk ID');
  assert(userMessage.includes('L1 to L30'), 'User message contains correct line range');
  assert(userMessage.includes('jwt.sign'), 'User message contains actual code content');

  // ---------------------------------------------------------
  // TEST 3: Groq SDK initialization with GROQ_LLAMA_PHASE_2 key
  // ---------------------------------------------------------
  console.log('\n--- Test 3: Groq SDK & GROQ_LLAMA_PHASE_2 API Key ---');
  const apiKey = process.env.GROQ_LLAMA_PHASE_2;
  assert(typeof apiKey === 'string' && apiKey.length > 10,
    `GROQ_LLAMA_PHASE_2 API key is loaded from .env (length: ${apiKey?.length})`);

  let groqClient = null;
  try {
    groqClient = new Groq({ apiKey });
    assert(groqClient !== null, 'Groq SDK client initialized successfully with GROQ_LLAMA_PHASE_2 key');
  } catch (initErr) {
    assert(false, `Groq SDK initialization failed: ${initErr.message}`);
  }

  // ---------------------------------------------------------
  // TEST 4: Live Groq LLaMA 3.3 70B API call & JSON schema validation
  // ---------------------------------------------------------
  console.log('\n--- Test 4: Live Groq LLaMA Evidence Extraction ---');
  if (groqClient) {
    try {
      const completion = await groqClient.chat.completions.create({
        messages: [
          { role: 'system', content: PHASE_2_SYSTEM_PROMPT },
          { role: 'user', content: buildUserMessage(sampleChunk) }
        ],
        model: 'llama-3.3-70b-versatile',
        temperature: 0.1,
        max_completion_tokens: 2048,
        response_format: { type: 'json_object' }
      });

      const rawContent = completion.choices[0]?.message?.content;
      assert(typeof rawContent === 'string' && rawContent.length > 0,
        'Groq LLaMA 3.3 70B returned non-empty response');

      let parsed;
      try {
        parsed = JSON.parse(rawContent);
      } catch (jsonErr) {
        assert(false, `Groq response is not valid JSON: ${jsonErr.message}`);
        parsed = null;
      }

      if (parsed) {
        assert(Array.isArray(parsed.nodes), 'Response contains "nodes" array');
        assert(Array.isArray(parsed.edges), 'Response contains "edges" array');
        assert(typeof parsed.language === 'string', 'Response contains "language" field');

        const forbiddenTerms = ['SQL Injection', 'XSS', 'CSRF', 'SSRF', 'Path Traversal', 'OWASP', 'CVE', 'CWE'];
        const rawStr = JSON.stringify(parsed);
        forbiddenTerms.forEach((term) => {
          assert(!rawStr.includes(term), `Response does NOT contain forbidden term "${term}"`);
        });

        // Validate node structure
        if (parsed.nodes.length > 0) {
          const firstNode = parsed.nodes[0];
          assert(typeof firstNode.id === 'string', 'Node has "id" field (string)');
          assert(typeof firstNode.type === 'string', 'Node has "type" field (string)');
          assert(typeof firstNode.confidence === 'number', 'Node has "confidence" field (number)');
          assert(firstNode.confidence >= 0 && firstNode.confidence <= 1.0,
            `Node confidence (${firstNode.confidence}) is in range [0.0, 1.0]`);
          console.log(`   ↳ Extracted ${parsed.nodes.length} nodes & ${parsed.edges.length} edges from sample server.js login route`);
          console.log(`   ↳ Frameworks detected: ${JSON.stringify(parsed.frameworks || [])}`);
        } else {
          console.log('   ↳ No nodes extracted from sample chunk (acceptable for this test input)');
        }
      }
    } catch (apiErr) {
      assert(false, `Groq API call failed: ${apiErr.message}`);
    }
  }

  console.log('\n==================================================');
  console.log(`TEST SUITE COMPLETE: ${passed} PASSED, ${failed} FAILED`);
  console.log('==================================================\n');

  if (failed > 0) process.exit(1);
}

runEvidenceTests().catch((err) => {
  console.error('Evidence test runner encountered an unexpected error:', err);
  process.exit(1);
});
