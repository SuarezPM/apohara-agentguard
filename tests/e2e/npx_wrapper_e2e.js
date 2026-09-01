#!/usr/bin/env node
// E2E tests for packaging/npx-wrapper/bin/apohara-agentguard.js
// Run: node tests/e2e/npx_wrapper_e2e.js

const path = require('path');
const fs = require('fs');
const os = require('os');

const WRAPPER = path.resolve(__dirname, '../../packaging/npx-wrapper/bin/apohara-agentguard.js');

// Load the wrapper's exported functions (it exports when not main)
const wrapper = require(WRAPPER);

let pass = 0, fail = 0, total = 0;

function test(name, fn) {
  total++;
  try {
    fn();
    pass++;
    console.log(`  ✅ ${name}`);
  } catch (e) {
    fail++;
    console.log(`  ❌ ${name}: ${e.message}`);
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'Assertion failed');
}

console.log('=== npx wrapper E2E tests ===\n');

// Test 1: VERSION is defined
console.log('Test 1: VERSION export');
test('VERSION is a string matching semver', () => {
  assert(typeof wrapper.VERSION === 'string', `Got ${typeof wrapper.VERSION}`);
  assert(/^\d+\.\d+\.\d+/.test(wrapper.VERSION), `Invalid version: ${wrapper.VERSION}`);
});

// Test 2: resolveTarget on current platform
console.log('Test 2: resolveTarget');
test('resolveTarget returns { triple, bin } for current platform', () => {
  const result = wrapper.resolveTarget();
  assert(typeof result === 'object' && result !== null, `Got ${typeof result}`);
  assert(typeof result.triple === 'string', `triple is ${typeof result.triple}`);
  assert(typeof result.bin === 'string', `bin is ${typeof result.bin}`);
});

test('triple contains known platform identifier', () => {
  const { triple } = wrapper.resolveTarget();
  const valid = triple.includes('linux') || triple.includes('apple') || triple.includes('darwin')
    || triple.includes('windows') || triple.includes('pc-windows');
  assert(valid, `Unexpected triple: ${triple}`);
});

test('triple follows Rust target triple format', () => {
  const { triple } = wrapper.resolveTarget();
  // Should have at least 3 segments separated by '-'
  const parts = triple.split('-');
  assert(parts.length >= 3, `Expected >= 3 dash-separated segments, got ${parts.length}: ${triple}`);
});

test('bin name matches platform convention', () => {
  const { bin } = wrapper.resolveTarget();
  if (process.platform === 'win32') {
    assert(bin.endsWith('.exe'), `Windows bin should end with .exe: ${bin}`);
  } else {
    assert(!bin.includes('.exe'), `Non-Windows bin should not have .exe: ${bin}`);
  }
});

// Test 3: parseChecksums
console.log('Test 3: parseChecksums');
test('parseChecksums returns a Map', () => {
  const content = 'abc123def456abc123def456abc123def456abc123def456abc123def456abcd *binary-name\n';
  const result = wrapper.parseChecksums(content);
  assert(typeof result === 'object', `Got ${typeof result}`);
  // Should be a Map (has get method)
  assert(typeof result.get === 'function', 'parseChecksums should return a Map');
  assert(result.size > 0, 'No entries parsed');
});

test('parseChecksums resolves hash for known artifact', () => {
  const content = 'abc123def456abc123def456abc123def456abc123def456abc123def456abcd *my-binary\n';
  const result = wrapper.parseChecksums(content);
  assert(result.get('my-binary') === 'abc123def456abc123def456abc123def456abc123def456abc123def456abcd',
    'Hash mismatch for known artifact');
});

test('parseChecksums returns undefined for missing artifact', () => {
  const content = 'abc123def456abc123def456abc123def456abc123def456abc123def456abcd *other-binary\n';
  const result = wrapper.parseChecksums(content);
  assert(result.get('nonexistent-binary') === undefined, 'Should return undefined for missing entry');
});

test('parseChecksums handles multiple lines', () => {
  const HASH1 = 'aabbccddee112233'.repeat(4); // exactly 64 hex chars
  const HASH2 = '1122334455667788'.repeat(4);
  assert(HASH1.length === 64 && HASH2.length === 64, 'Test setup: hashes must be 64 chars');
  const content = `${HASH1} *alpha\n${HASH2} *bravo\n\n`;
  const result = wrapper.parseChecksums(content);
  assert(result.size === 2, `Expected 2 entries, got ${result.size}`);
});

test('parseChecksums lowercases hashes', () => {
  const HEX64 = 'AABBCCDDEE112233'.repeat(4); // 64 chars with uppercase
  assert(HEX64.length === 64, 'Test setup: hash must be 64 chars');
  const content = `${HEX64} *test\n`;
  const result = wrapper.parseChecksums(content);
  const hash = result.get('test');
  assert(hash === hash.toLowerCase(), 'Hash should be lowercased');
});

// Test 4: sha256 function
console.log('Test 4: sha256');
test('sha256 returns 64-char hex string from Buffer', () => {
  const buf = Buffer.from('hello world');
  const hash = wrapper.sha256(buf);
  assert(typeof hash === 'string', `Got ${typeof hash}`);
  assert(hash.length === 64, `Expected 64 chars, got ${hash.length}`);
  assert(/^[0-9a-f]+$/.test(hash), `Not hex: ${hash}`);
});

test('sha256 produces correct hash for known input', () => {
  // SHA256 of "hello world" is known
  const expected = 'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
  const buf = Buffer.from('hello world');
  const hash = wrapper.sha256(buf);
  assert(hash === expected, `Expected ${expected}, got ${hash}`);
});

test('sha256 produces different hashes for different inputs', () => {
  const hash1 = wrapper.sha256(Buffer.from('input-a'));
  const hash2 = wrapper.sha256(Buffer.from('input-b'));
  assert(hash1 !== hash2, 'Different inputs should produce different hashes');
});

// Test 5: isMusl detection
console.log('Test 5: isMusl');
test('isMusl returns boolean', () => {
  const result = wrapper.isMusl();
  assert(typeof result === 'boolean', `Got ${typeof result}`);
});

test('isMusl is false on non-Linux platforms', () => {
  if (process.platform !== 'linux') {
    assert(wrapper.isMusl() === false, 'isMusl should be false on non-Linux');
  }
});

// Test 6: Module structure sanity
console.log('Test 6: Module exports');
test('wrapper exports all expected keys', () => {
  const expectedKeys = ['resolveTarget', 'isMusl', 'sha256', 'parseChecksums', 'VERSION'];
  for (const key of expectedKeys) {
    assert(typeof wrapper[key] === 'function' || typeof wrapper[key] === 'string',
      `Expected ${key} to be function or string, got ${typeof wrapper[key]}`);
  }
});

// Summary
console.log(`\n=== Results: ${pass}/${total} passed, ${fail} failed ===`);
process.exit(fail === 0 ? 0 : 1);
