/**
 * CRYPT//CORE — CLASSICAL CRYPTOGRAPHY TOOLKIT
 * Final Year Network Security Mini Project (Academic Year 2026-27)
 * Electronics and Computer Engineering
 * 
 * Modular implementation of 8 classical ciphers, key validation,
 * performance benchmarking, client-side file tools, and automated self-tests.
 */

'use strict';

/* ==========================================================================
   1. SHARED UTILITIES & MATHEMATICAL HELPERS
   ========================================================================== */

/**
 * Standard positive modulo helper: ((n % m) + m) % m
 */
function mod(n, m) {
  return ((n % m) + m) % m;
}

/**
 * Greatest Common Divisor (Euclidean algorithm)
 */
function gcd(a, b) {
  a = Math.abs(a);
  b = Math.abs(b);
  while (b) {
    const t = b;
    b = a % b;
    a = t;
  }
  return a;
}

/**
 * Modular multiplicative inverse modulo 26.
 * Returns inverse in 0..25 if gcd(a, 26) === 1, else null.
 */
function modInverse26(a) {
  a = mod(a, 26);
  for (let x = 1; x < 26; x++) {
    if ((a * x) % 26 === 1) {
      return x;
    }
  }
  return null;
}

/**
 * Checks if a character is an English letter (A-Z, a-z)
 */
function isLetter(ch) {
  return /^[A-Za-z]$/.test(ch);
}

/**
 * Checks if a character is uppercase
 */
function isUpperCase(ch) {
  return ch >= 'A' && ch <= 'Z';
}

/**
 * Filters a string to uppercase alphabetic letters only
 */
function cleanAlphaOnly(text) {
  return (text || '').toUpperCase().replace(/[^A-Z]/g, '');
}

/**
 * Generates a cryptographically random string of uppercase letters
 */
function generateRandomAlphabetString(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const array = new Uint8Array(length);
  window.crypto.getRandomValues(array);
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars[array[i] % 26];
  }
  return result;
}

/* ==========================================================================
   2. ALGORITHM IMPLEMENTATIONS
   ========================================================================== */

/**
 * --------------------------------------------------------------------------
 * 1. CAESAR CIPHER
 * --------------------------------------------------------------------------
 * C_i = (P_i + k) mod 26
 * Preserves uppercase/lowercase and all non-alphabetic characters.
 */
function caesarEncrypt(text, shift) {
  const k = mod(parseInt(shift, 10) || 0, 26);
  let result = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch >= 'A' && ch <= 'Z') {
      result += String.fromCharCode(((ch.charCodeAt(0) - 65 + k) % 26) + 65);
    } else if (ch >= 'a' && ch <= 'z') {
      result += String.fromCharCode(((ch.charCodeAt(0) - 97 + k) % 26) + 97);
    } else {
      result += ch;
    }
  }
  return result;
}

function caesarDecrypt(text, shift) {
  const k = mod(parseInt(shift, 10) || 0, 26);
  return caesarEncrypt(text, 26 - k);
}

/**
 * --------------------------------------------------------------------------
 * 2. MONOALPHABETIC SUBSTITUTION CIPHER
 * --------------------------------------------------------------------------
 * Bijective 26-letter substitution mapping.
 */
function validateMonoKey(key) {
  const clean = cleanAlphaOnly(key);
  if (clean.length !== 26) {
    return { valid: false, error: 'Key must contain exactly 26 letters.' };
  }
  const unique = new Set(clean);
  if (unique.size !== 26) {
    return { valid: false, error: 'Key contains duplicate letters. All 26 letters must be unique.' };
  }
  return { valid: true, cleanKey: clean };
}

function monoalphabeticEncrypt(text, key) {
  const validation = validateMonoKey(key);
  if (!validation.valid) throw new Error(validation.error);
  const mapKey = validation.cleanKey;

  let result = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch >= 'A' && ch <= 'Z') {
      const idx = ch.charCodeAt(0) - 65;
      result += mapKey[idx];
    } else if (ch >= 'a' && ch <= 'z') {
      const idx = ch.charCodeAt(0) - 97;
      result += mapKey[idx].toLowerCase();
    } else {
      result += ch;
    }
  }
  return result;
}

function monoalphabeticDecrypt(text, key) {
  const validation = validateMonoKey(key);
  if (!validation.valid) throw new Error(validation.error);
  const mapKey = validation.cleanKey;

  // Build reverse mapping table
  const reverseUpper = {};
  const reverseLower = {};
  for (let i = 0; i < 26; i++) {
    const origCharUpper = String.fromCharCode(65 + i);
    const origCharLower = String.fromCharCode(97 + i);
    const mappedCharUpper = mapKey[i];
    reverseUpper[mappedCharUpper] = origCharUpper;
    reverseLower[mappedCharUpper.toLowerCase()] = origCharLower;
  }

  let result = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (reverseUpper[ch]) {
      result += reverseUpper[ch];
    } else if (reverseLower[ch]) {
      result += reverseLower[ch];
    } else {
      result += ch;
    }
  }
  return result;
}

function generateRandomMonoKey() {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');
  // Fisher-Yates shuffle
  for (let i = alphabet.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    const temp = alphabet[i];
    alphabet[i] = alphabet[j];
    alphabet[j] = temp;
  }
  return alphabet.join('');
}

/**
 * --------------------------------------------------------------------------
 * 3. PLAYFAIR CIPHER
 * --------------------------------------------------------------------------
 * Digraph substitution on a 5×5 key matrix (I and J combined).
 */
function buildPlayfairMatrix(keyword) {
  const cleanKey = cleanAlphaOnly(keyword).replace(/J/g, 'I');
  const seen = new Set();
  const matrixChars = [];

  for (const ch of cleanKey) {
    if (!seen.has(ch)) {
      seen.add(ch);
      matrixChars.push(ch);
    }
  }

  const standard = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'; // J omitted
  for (const ch of standard) {
    if (!seen.has(ch)) {
      seen.add(ch);
      matrixChars.push(ch);
    }
  }

  const matrix = [];
  const charPos = {};
  for (let r = 0; r < 5; r++) {
    matrix[r] = [];
    for (let c = 0; c < 5; c++) {
      const ch = matrixChars[r * 5 + c];
      matrix[r][c] = ch;
      charPos[ch] = { row: r, col: c };
    }
  }

  return { matrix, charPos, flat: matrixChars };
}

function playfairEncrypt(text, keyword) {
  if (!cleanAlphaOnly(keyword)) {
    throw new Error('Playfair cipher requires an alphabetic keyword.');
  }
  const { matrix, charPos } = buildPlayfairMatrix(keyword);
  const clean = cleanAlphaOnly(text).replace(/J/g, 'I');
  if (clean.length === 0) return '';

  // Form digraphs with filler 'X' (or 'Q' if repeated char is 'X')
  const digraphs = [];
  let i = 0;
  while (i < clean.length) {
    const a = clean[i];
    if (i + 1 < clean.length) {
      const b = clean[i + 1];
      if (a === b) {
        digraphs.push([a, a === 'X' ? 'Q' : 'X']);
        i += 1;
      } else {
        digraphs.push([a, b]);
        i += 2;
      }
    } else {
      digraphs.push([a, a === 'X' ? 'Q' : 'X']);
      i += 1;
    }
  }

  let result = '';
  for (const [a, b] of digraphs) {
    const p1 = charPos[a];
    const p2 = charPos[b];

    if (p1.row === p2.row) {
      // Same row: shift right
      result += matrix[p1.row][(p1.col + 1) % 5];
      result += matrix[p2.row][(p2.col + 1) % 5];
    } else if (p1.col === p2.col) {
      // Same column: shift down
      result += matrix[(p1.row + 1) % 5][p1.col];
      result += matrix[(p2.row + 1) % 5][p2.col];
    } else {
      // Rectangle: swap columns
      result += matrix[p1.row][p2.col];
      result += matrix[p2.row][p1.col];
    }
  }
  return result;
}

function playfairDecrypt(ciphertext, keyword) {
  if (!cleanAlphaOnly(keyword)) {
    throw new Error('Playfair cipher requires an alphabetic keyword.');
  }
  const { matrix, charPos } = buildPlayfairMatrix(keyword);
  const clean = cleanAlphaOnly(ciphertext).replace(/J/g, 'I');
  if (clean.length === 0) return '';
  if (clean.length % 2 !== 0) {
    throw new Error('Playfair ciphertext must contain an even number of letters.');
  }

  let result = '';
  for (let i = 0; i < clean.length; i += 2) {
    const a = clean[i];
    const b = clean[i + 1];
    const p1 = charPos[a];
    const p2 = charPos[b];

    if (!p1 || !p2) {
      throw new Error(`Character '${!p1 ? a : b}' not found in Playfair matrix.`);
    }

    if (p1.row === p2.row) {
      // Same row: shift left
      result += matrix[p1.row][(p1.col + 4) % 5];
      result += matrix[p2.row][(p2.col + 4) % 5];
    } else if (p1.col === p2.col) {
      // Same column: shift up
      result += matrix[(p1.row + 4) % 5][p1.col];
      result += matrix[(p2.row + 4) % 5][p2.col];
    } else {
      // Rectangle: swap columns
      result += matrix[p1.row][p2.col];
      result += matrix[p2.row][p1.col];
    }
  }
  return result;
}

/**
 * --------------------------------------------------------------------------
 * 4. HILL CIPHER (2×2)
 * --------------------------------------------------------------------------
 * C = K * P mod 26
 * Validates gcd(det(K), 26) === 1 and computes K^(-1) mod 26.
 */
function validateHillKey2x2(k00, k01, k10, k11) {
  k00 = mod(parseInt(k00, 10) || 0, 26);
  k01 = mod(parseInt(k01, 10) || 0, 26);
  k10 = mod(parseInt(k10, 10) || 0, 26);
  k11 = mod(parseInt(k11, 10) || 0, 26);

  const rawDet = k00 * k11 - k01 * k10;
  const det = mod(rawDet, 26);
  const commonDiv = gcd(det, 26);

  if (commonDiv !== 1) {
    return {
      valid: false,
      det,
      error: `Matrix determinant (${det}) is NOT coprime with 26 (gcd=${commonDiv}). Inverse does not exist mod 26. Try an invertible matrix like [3, 3, 2, 5].`
    };
  }

  const detInv = modInverse26(det);
  if (detInv === null) {
    return { valid: false, det, error: 'Modular inverse of determinant does not exist.' };
  }

  // Inverse matrix: K^(-1) = detInv * [k11, -k01; -k10, k00] mod 26
  const inv00 = mod(detInv * k11, 26);
  const inv01 = mod(detInv * (-k01), 26);
  const inv10 = mod(detInv * (-k10), 26);
  const inv11 = mod(detInv * k00, 26);

  return {
    valid: true,
    matrix: [
      [k00, k01],
      [k10, k11]
    ],
    invMatrix: [
      [inv00, inv01],
      [inv10, inv11]
    ],
    det,
    detInv
  };
}

function hillEncrypt(text, k00, k01, k10, k11) {
  const validation = validateHillKey2x2(k00, k01, k10, k11);
  if (!validation.valid) throw new Error(validation.error);

  let clean = cleanAlphaOnly(text);
  if (clean.length === 0) return '';
  // Pad with 'X' if odd length
  if (clean.length % 2 !== 0) {
    clean += 'X';
  }

  const K = validation.matrix;
  let result = '';
  for (let i = 0; i < clean.length; i += 2) {
    const p0 = clean.charCodeAt(i) - 65;
    const p1 = clean.charCodeAt(i + 1) - 65;

    const c0 = mod(K[0][0] * p0 + K[0][1] * p1, 26);
    const c1 = mod(K[1][0] * p0 + K[1][1] * p1, 26);

    result += String.fromCharCode(65 + c0);
    result += String.fromCharCode(65 + c1);
  }
  return result;
}

function hillDecrypt(ciphertext, k00, k01, k10, k11) {
  const validation = validateHillKey2x2(k00, k01, k10, k11);
  if (!validation.valid) throw new Error(validation.error);

  let clean = cleanAlphaOnly(ciphertext);
  if (clean.length === 0) return '';
  if (clean.length % 2 !== 0) {
    clean += 'X';
  }

  const InvK = validation.invMatrix;
  let result = '';
  for (let i = 0; i < clean.length; i += 2) {
    const c0 = clean.charCodeAt(i) - 65;
    const c1 = clean.charCodeAt(i + 1) - 65;

    const p0 = mod(InvK[0][0] * c0 + InvK[0][1] * c1, 26);
    const p1 = mod(InvK[1][0] * c0 + InvK[1][1] * c1, 26);

    result += String.fromCharCode(65 + p0);
    result += String.fromCharCode(65 + p1);
  }
  return result;
}

/**
 * --------------------------------------------------------------------------
 * 5. VIGENÈRE CIPHER
 * --------------------------------------------------------------------------
 * Polyalphabetic repeating keyword shift across alphabetic letters.
 * Preserves case and punctuation. Advances keyword pointer only on letters.
 */
function vigenereEncrypt(text, keyword) {
  const cleanKey = cleanAlphaOnly(keyword);
  if (!cleanKey) {
    throw new Error('Vigenère cipher requires an alphabetic keyword.');
  }

  let result = '';
  let keyIndex = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch >= 'A' && ch <= 'Z') {
      const shift = cleanKey.charCodeAt(keyIndex % cleanKey.length) - 65;
      result += String.fromCharCode(((ch.charCodeAt(0) - 65 + shift) % 26) + 65);
      keyIndex++;
    } else if (ch >= 'a' && ch <= 'z') {
      const shift = cleanKey.charCodeAt(keyIndex % cleanKey.length) - 65;
      result += String.fromCharCode(((ch.charCodeAt(0) - 97 + shift) % 26) + 97);
      keyIndex++;
    } else {
      result += ch;
    }
  }
  return result;
}

function vigenereDecrypt(text, keyword) {
  const cleanKey = cleanAlphaOnly(keyword);
  if (!cleanKey) {
    throw new Error('Vigenère cipher requires an alphabetic keyword.');
  }

  let result = '';
  let keyIndex = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch >= 'A' && ch <= 'Z') {
      const shift = cleanKey.charCodeAt(keyIndex % cleanKey.length) - 65;
      result += String.fromCharCode(mod(ch.charCodeAt(0) - 65 - shift, 26) + 65);
      keyIndex++;
    } else if (ch >= 'a' && ch <= 'z') {
      const shift = cleanKey.charCodeAt(keyIndex % cleanKey.length) - 65;
      result += String.fromCharCode(mod(ch.charCodeAt(0) - 97 - shift, 26) + 97);
      keyIndex++;
    } else {
      result += ch;
    }
  }
  return result;
}

/**
 * --------------------------------------------------------------------------
 * 6. ONE-TIME PAD (VERNAM CIPHER)
 * --------------------------------------------------------------------------
 * Strictly requires key length >= alphabetic length of message.
 * Never silently repeats key (Shannon secrecy constraint).
 * Preserves case and punctuation.
 */
function otpEncrypt(text, key) {
  const cleanKey = cleanAlphaOnly(key);
  const alphaCharsInText = text.replace(/[^A-Za-z]/g, '').length;

  if (cleanKey.length < alphaCharsInText) {
    throw new Error(
      `One-Time Pad key length (${cleanKey.length}) is shorter than the text's alphabetic letters (${alphaCharsInText}). Under Shannon's theorem, an OTP key must be at least as long as the plaintext and NEVER repeated.`
    );
  }

  let result = '';
  let keyIndex = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch >= 'A' && ch <= 'Z') {
      const shift = cleanKey.charCodeAt(keyIndex) - 65;
      result += String.fromCharCode(((ch.charCodeAt(0) - 65 + shift) % 26) + 65);
      keyIndex++;
    } else if (ch >= 'a' && ch <= 'z') {
      const shift = cleanKey.charCodeAt(keyIndex) - 65;
      result += String.fromCharCode(((ch.charCodeAt(0) - 97 + shift) % 26) + 97);
      keyIndex++;
    } else {
      result += ch;
    }
  }
  return result;
}

function otpDecrypt(text, key) {
  const cleanKey = cleanAlphaOnly(key);
  const alphaCharsInText = text.replace(/[^A-Za-z]/g, '').length;

  if (cleanKey.length < alphaCharsInText) {
    throw new Error(
      `One-Time Pad key length (${cleanKey.length}) is shorter than the text's alphabetic letters (${alphaCharsInText}).`
    );
  }

  let result = '';
  let keyIndex = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch >= 'A' && ch <= 'Z') {
      const shift = cleanKey.charCodeAt(keyIndex) - 65;
      result += String.fromCharCode(mod(ch.charCodeAt(0) - 65 - shift, 26) + 65);
      keyIndex++;
    } else if (ch >= 'a' && ch <= 'z') {
      const shift = cleanKey.charCodeAt(keyIndex) - 65;
      result += String.fromCharCode(mod(ch.charCodeAt(0) - 97 - shift, 26) + 97);
      keyIndex++;
    } else {
      result += ch;
    }
  }
  return result;
}

/**
 * --------------------------------------------------------------------------
 * 7. RAIL FENCE CIPHER (ZIGZAG TRANSPOSITION)
 * --------------------------------------------------------------------------
 * Writes characters along zigzag rails (>= 2).
 * Preserves all characters (including spaces and punctuation).
 */
function railFenceEncrypt(text, rails) {
  const r = parseInt(rails, 10);
  if (isNaN(r) || r < 2) {
    throw new Error('Rail Fence cipher requires rail count >= 2.');
  }
  if (!text || text.length <= r) return text;

  const railArrays = Array.from({ length: r }, () => []);
  let currentRail = 0;
  let goingDown = true;

  for (let i = 0; i < text.length; i++) {
    railArrays[currentRail].push(text[i]);

    if (currentRail === 0) {
      goingDown = true;
    } else if (currentRail === r - 1) {
      goingDown = false;
    }
    currentRail += goingDown ? 1 : -1;
  }

  return railArrays.map(row => row.join('')).join('');
}

function railFenceDecrypt(ciphertext, rails) {
  const r = parseInt(rails, 10);
  if (isNaN(r) || r < 2) {
    throw new Error('Rail Fence cipher requires rail count >= 2.');
  }
  if (!ciphertext || ciphertext.length <= r) return ciphertext;

  // Determine zigzag coordinates
  const railMarkers = Array.from({ length: r }, () => []);
  let currentRail = 0;
  let goingDown = true;

  for (let i = 0; i < ciphertext.length; i++) {
    railMarkers[currentRail].push(i);

    if (currentRail === 0) {
      goingDown = true;
    } else if (currentRail === r - 1) {
      goingDown = false;
    }
    currentRail += goingDown ? 1 : -1;
  }

  // Populate characters into marked rail positions
  const plaintextArr = new Array(ciphertext.length);
  let charIdx = 0;

  for (let rail = 0; rail < r; rail++) {
    for (const pos of railMarkers[rail]) {
      plaintextArr[pos] = ciphertext[charIdx++];
    }
  }

  return plaintextArr.join('');
}

/**
 * --------------------------------------------------------------------------
 * 8. COLUMNAR TRANSPOSITION CIPHER
 * --------------------------------------------------------------------------
 * Writes plaintext into rows of length = keyword.length.
 * Reads out columns in alphabetical order of keyword letters.
 * Handles duplicate keyword letters deterministically.
 * Uses irregular grid columns to guarantee lossless roundtrip without padding corruption.
 */
function getColumnarOrder(keyword) {
  const cleanKey = cleanAlphaOnly(keyword);
  if (!cleanKey) {
    throw new Error('Columnar Transposition requires an alphabetic keyword.');
  }

  // Create array of { char, originalIndex }
  const indexed = cleanKey.split('').map((char, index) => ({ char, index }));
  
  // Stable sort: primary by char ascending, secondary by original index ascending
  indexed.sort((a, b) => {
    if (a.char < b.char) return -1;
    if (a.char > b.char) return 1;
    return a.index - b.index;
  });

  return {
    keyLength: cleanKey.length,
    readOrder: indexed.map(item => item.index), // which original column to read in order
    cleanKey
  };
}

function columnarEncrypt(text, keyword) {
  if (!text) return '';
  const { keyLength, readOrder } = getColumnarOrder(keyword);

  // Group characters into original columns
  const columns = Array.from({ length: keyLength }, () => []);
  for (let i = 0; i < text.length; i++) {
    const col = i % keyLength;
    columns[col].push(text[i]);
  }

  // Read out columns in alphabetical priority order
  let result = '';
  for (const colIdx of readOrder) {
    result += columns[colIdx].join('');
  }
  return result;
}

function columnarDecrypt(ciphertext, keyword) {
  if (!ciphertext) return '';
  const { keyLength, readOrder } = getColumnarOrder(keyword);
  const textLen = ciphertext.length;

  // Determine lengths of each original column
  const fullRows = Math.floor(textLen / keyLength);
  const remainder = textLen % keyLength;

  const colLengths = new Array(keyLength).fill(fullRows);
  for (let c = 0; c < remainder; c++) {
    colLengths[c] += 1;
  }

  // Slice ciphertext into columns based on readOrder
  const originalColumns = Array.from({ length: keyLength }, () => []);
  let textIndex = 0;

  for (const colIdx of readOrder) {
    const len = colLengths[colIdx];
    originalColumns[colIdx] = ciphertext.slice(textIndex, textIndex + len).split('');
    textIndex += len;
  }

  // Reconstruct message row by row
  let result = '';
  for (let i = 0; i < textLen; i++) {
    const col = i % keyLength;
    result += originalColumns[col].shift();
  }

  return result;
}

/* ==========================================================================
   3. CIPHER METADATA CATALOG
   ========================================================================== */

const CIPHER_REGISTRY = {
  caesar: {
    id: 'caesar',
    name: 'Caesar Cipher',
    family: 'substitution',
    familyLabel: 'SUBSTITUTION',
    formula: 'C = (P + k) mod 26 | P = (C - k + 26) mod 26',
    desc: 'Shifts each alphabetic character forward by a numeric key k. Preserves letter case and punctuation.',
    defaultKey: 3,
    sampleInput: 'NETWORK SECURITY'
  },
  monoalphabetic: {
    id: 'monoalphabetic',
    name: 'Monoalphabetic Cipher',
    family: 'substitution',
    familyLabel: 'SUBSTITUTION',
    formula: 'C = Map[P] | P = Map⁻¹[C] (26-character permutation)',
    desc: 'Substitutes each letter with a fixed corresponding character from a 26-letter scrambled alphabet.',
    defaultKey: 'QWERTYUIOPASDFGHJKLZXCVBNM',
    sampleInput: 'DEFEND THE EAST WALL OF THE CASTLE'
  },
  playfair: {
    id: 'playfair',
    name: 'Playfair Cipher',
    family: 'substitution',
    familyLabel: 'POLYGRAPHIC',
    formula: 'Digraph matrix coordinates: Row shift, Column shift, or Rectangle swap',
    desc: 'Encrypts pairs of letters using a 5×5 key grid combining I/J. Inserts filler X for repeated digraph letters.',
    defaultKey: 'MONARCHY',
    sampleInput: 'INSTRUMENTS'
  },
  hill: {
    id: 'hill',
    name: 'Hill Cipher (2×2)',
    family: 'substitution',
    familyLabel: 'POLYGRAPHIC',
    formula: 'C = K · P mod 26 | P = K⁻¹ · C mod 26 | gcd(det(K), 26) = 1',
    desc: 'Linear algebra modular matrix transformation. Input is converted to uppercase letter vectors (padded with X if odd).',
    defaultKey: { k00: 3, k01: 3, k10: 2, k11: 5 },
    sampleInput: 'HELP'
  },
  vigenere: {
    id: 'vigenere',
    name: 'Vigenère Cipher',
    family: 'substitution',
    familyLabel: 'POLYALPHABETIC',
    formula: 'C_i = (P_i + K_j) mod 26 | P_i = (P_i - K_j + 26) mod 26',
    desc: 'Repeating keyword shifts based on the Tabula Recta. Advance keyword only across alphabetic letters.',
    defaultKey: 'LEMON',
    sampleInput: 'ATTACKATDAWN'
  },
  otp: {
    id: 'otp',
    name: 'One-Time Pad (Vernam)',
    family: 'substitution',
    familyLabel: 'POLYALPHABETIC',
    formula: 'C_i = (P_i + K_i) mod 26 | Key length ≥ Message length (Unrepeated)',
    desc: 'Information-theoretically secure if key is truly random, never reused, kept secret, and at least as long as text.',
    defaultKey: 'SECRETKEYFORONETIMEPADVERIFICATION2027',
    sampleInput: 'NETWORK SECURITY'
  },
  railfence: {
    id: 'railfence',
    name: 'Rail Fence Cipher',
    family: 'transposition',
    familyLabel: 'TRANSPOSITION',
    formula: 'Zigzag diagonal trajectory across R parallel rails',
    desc: 'Transposition cipher writing characters along diagonal rails and reading rows sequentially.',
    defaultKey: 3,
    sampleInput: 'WEAREDISCOVEREDFLEEATONCE'
  },
  columnar: {
    id: 'columnar',
    name: 'Columnar Transposition',
    family: 'transposition',
    familyLabel: 'TRANSPOSITION',
    formula: 'Permutes columns according to alphabetical rank of keyword letters',
    desc: 'Grid transposition reading columns sorted by keyword character order. Supports irregular grids losslessly.',
    defaultKey: 'GERMAN',
    sampleInput: 'DEFEND THE EAST WALL AT DAWN'
  }
};

/* ==========================================================================
   4. APPLICATION STATE & DOM BINDINGS
   ========================================================================== */

const AppState = {
  currentCipher: 'caesar',
  currentMode: 'encrypt', // 'encrypt' or 'decrypt'
  familyFilter: 'all',
  lastExecutionResult: '',
  fileData: {
    name: '',
    size: 0,
    text: '',
    processedText: ''
  }
};

// Cached DOM Elements
const DOM = {};

function initDOMElements() {
  DOM.textInput = document.getElementById('text-input');
  DOM.outputDisplay = document.getElementById('output-display');
  DOM.activeCipherTitle = document.getElementById('active-cipher-title');
  DOM.activeFamilyTag = document.getElementById('active-family-tag');
  DOM.activeCipherFormula = document.getElementById('active-cipher-formula');
  DOM.activeCipherDesc = document.getElementById('active-cipher-desc');
  DOM.dynamicKeyContainer = document.getElementById('dynamic-key-container');
  DOM.keyHelpHint = document.getElementById('key-help-hint');
  DOM.keyToolbar = document.getElementById('key-toolbar');
  DOM.keyValidationMsg = document.getElementById('key-validation-message');
  DOM.visualMatrixPanel = document.getElementById('visual-matrix-panel');
  DOM.matrixDisplay = document.getElementById('matrix-display');
  DOM.matrixTitleText = document.getElementById('matrix-title-text');
  DOM.matrixStatusTag = document.getElementById('matrix-status-tag');
  DOM.executeBtn = document.getElementById('execute-btn');
  DOM.executeBtnLabel = document.getElementById('execute-btn-label');
  DOM.swapBtn = document.getElementById('swap-btn');
  DOM.clearBtn = document.getElementById('clear-btn');
  DOM.copyBtn = document.getElementById('copy-btn');
  DOM.downloadBtn = document.getElementById('download-btn');
  DOM.modeEncrypt = document.getElementById('mode-encrypt');
  DOM.modeDecrypt = document.getElementById('mode-decrypt');
  DOM.inputCharCount = document.getElementById('input-char-count');
  DOM.inputWordCount = document.getElementById('input-word-count');
  DOM.outputCharCount = document.getElementById('output-char-count');
  DOM.execTimeBadge = document.getElementById('exec-time-badge');
  DOM.terminalSessionTitle = document.getElementById('terminal-session-title');
  DOM.toastContainer = document.getElementById('toast-container');
  DOM.quickDemoBtn = document.getElementById('quick-demo-btn');
  DOM.ctaSampleDemo = document.getElementById('cta-sample-demo');

  // Comparison module
  DOM.compareTextInput = document.getElementById('compare-text-input');
  DOM.runCompareBtn = document.getElementById('run-compare-btn');
  DOM.comparisonTbody = document.getElementById('comparison-tbody');

  // File tools
  DOM.fileInput = document.getElementById('file-input');
  DOM.browseFileBtn = document.getElementById('browse-file-btn');
  DOM.fileDropZone = document.getElementById('file-drop-zone');
  DOM.fileMetaCard = document.getElementById('file-meta-card');
  DOM.fileNameVal = document.getElementById('file-name-val');
  DOM.fileSizeVal = document.getElementById('file-size-val');
  DOM.fileCharsVal = document.getElementById('file-chars-val');
  DOM.filePreviewText = document.getElementById('file-preview-text');
  DOM.fileCipherSelect = document.getElementById('file-cipher-select');
  DOM.fileKeyInput = document.getElementById('file-key-input');
  DOM.fileKeyHint = document.getElementById('file-key-hint');
  DOM.fileEncryptBtn = document.getElementById('file-encrypt-btn');
  DOM.fileDecryptBtn = document.getElementById('file-decrypt-btn');
  DOM.fileResultPreview = document.getElementById('file-result-preview');
  DOM.fileExecTime = document.getElementById('file-exec-time');
  DOM.fileDownloadBtn = document.getElementById('file-download-btn');

  // Test suite
  DOM.runAllTestsBtn = document.getElementById('run-all-tests-btn');
  DOM.testResultsList = document.getElementById('test-results-list');
  DOM.testOverallStatus = document.getElementById('test-overall-status');
  DOM.testPassCount = document.getElementById('test-pass-count');
  DOM.testTotalTime = document.getElementById('test-total-time');

  // Exit Modal
  DOM.exitBtn = document.getElementById('exit-btn');
  DOM.exitModal = document.getElementById('exit-modal');
  DOM.modalCloseBtn = document.getElementById('modal-close-btn');
  DOM.modalCancelBtn = document.getElementById('modal-cancel-btn');
  DOM.modalResetBtn = document.getElementById('modal-reset-btn');

  // Nav Mobile
  DOM.navToggle = document.getElementById('nav-toggle');
  DOM.navMenu = document.getElementById('nav-menu');
}

/* ==========================================================================
   5. TOAST NOTIFICATIONS & FEEDBACK
   ========================================================================== */

function showToast(message, type = 'info', duration = 3200) {
  if (!DOM.toastContainer) return;

  const toast = document.createElement('div');
  toast.className = `cyber-toast toast-${type}`;
  toast.setAttribute('role', 'alert');

  let iconSvg = '';
  if (type === 'success') {
    iconSvg = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>`;
  } else if (type === 'error') {
    iconSvg = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;
  } else {
    iconSvg = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;
  }

  toast.innerHTML = `${iconSvg}<span>${message}</span>`;
  DOM.toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.25s ease';
    setTimeout(() => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 260);
  }, duration);
}

/* ==========================================================================
   6. UI CONTROLS & DYNAMIC KEY RENDERER
   ========================================================================== */

function setValidationMessage(msg, type = 'error') {
  if (!DOM.keyValidationMsg) return;
  if (!msg) {
    DOM.keyValidationMsg.className = 'validation-message';
    DOM.keyValidationMsg.style.display = 'none';
    DOM.keyValidationMsg.textContent = '';
  } else {
    DOM.keyValidationMsg.className = `validation-message ${type}`;
    DOM.keyValidationMsg.style.display = 'block';
    DOM.keyValidationMsg.textContent = msg;
  }
}

/**
 * Dynamically constructs input controls and matrix visualizers for active cipher
 */
function renderDynamicKeyControls(cipherId) {
  setValidationMessage('');
  DOM.dynamicKeyContainer.innerHTML = '';
  DOM.keyToolbar.innerHTML = '';
  DOM.visualMatrixPanel.classList.add('hidden');

  switch (cipherId) {
    case 'caesar': {
      DOM.keyHelpHint.textContent = 'Specify shift value (0 to 25)';
      const row = document.createElement('div');
      row.className = 'key-input-row';
      row.innerHTML = `
        <div class="key-slider-wrapper">
          <input type="range" id="caesar-slider" class="cyber-range" min="0" max="25" value="3" aria-label="Caesar shift slider">
          <span class="key-num-badge" id="caesar-badge">3</span>
        </div>
        <input type="number" id="caesar-num" class="cyber-input" min="0" max="25" value="3" style="width: 80px;" aria-label="Caesar shift number">
      `;
      DOM.dynamicKeyContainer.appendChild(row);

      const slider = row.querySelector('#caesar-slider');
      const num = row.querySelector('#caesar-num');
      const badge = row.querySelector('#caesar-badge');

      slider.addEventListener('input', () => {
        num.value = slider.value;
        badge.textContent = slider.value;
      });
      num.addEventListener('input', () => {
        const val = Math.max(0, Math.min(25, parseInt(num.value, 10) || 0));
        num.value = val;
        slider.value = val;
        badge.textContent = val;
      });
      break;
    }

    case 'monoalphabetic': {
      DOM.keyHelpHint.textContent = '26 unique English letters representing mapped alphabet (A-Z)';
      const input = document.createElement('input');
      input.type = 'text';
      input.id = 'mono-key-input';
      input.className = 'cyber-input';
      input.value = 'QWERTYUIOPASDFGHJKLZXCVBNM';
      input.maxLength = 26;
      input.setAttribute('aria-label', 'Monoalphabetic substitution key');
      DOM.dynamicKeyContainer.appendChild(input);

      // Random key button in toolbar
      const randBtn = document.createElement('button');
      randBtn.type = 'button';
      randBtn.className = 'btn btn-secondary btn-sm';
      randBtn.innerHTML = `
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
        Generate Random Key
      `;
      randBtn.addEventListener('click', () => {
        const randKey = generateRandomMonoKey();
        input.value = randKey;
        validateMonoKeyInput(randKey);
        showToast('Random 26-letter substitution alphabet generated.', 'info');
      });
      DOM.keyToolbar.appendChild(randBtn);

      input.addEventListener('input', () => {
        input.value = input.value.toUpperCase();
        validateMonoKeyInput(input.value);
      });
      break;
    }

    case 'playfair': {
      DOM.keyHelpHint.textContent = 'Keyword for 5×5 matrix (combining I and J)';
      const input = document.createElement('input');
      input.type = 'text';
      input.id = 'playfair-key-input';
      input.className = 'cyber-input';
      input.value = 'MONARCHY';
      input.placeholder = 'Enter keyword (e.g., MONARCHY)...';
      input.setAttribute('aria-label', 'Playfair keyword');
      DOM.dynamicKeyContainer.appendChild(input);

      DOM.visualMatrixPanel.classList.remove('hidden');
      DOM.matrixTitleText.textContent = 'PLAYFAIR 5×5 KEY MATRIX';
      DOM.matrixStatusTag.textContent = 'I/J Merged Polybius Grid';

      const updatePlayfairVisual = () => {
        const keyword = input.value;
        const { matrix, charPos } = buildPlayfairMatrix(keyword);
        const cleanKeyChars = new Set(cleanAlphaOnly(keyword).replace(/J/g, 'I').split(''));
        let tableHtml = '<table class="polybius-table">';
        for (let r = 0; r < 5; r++) {
          tableHtml += '<tr>';
          for (let c = 0; c < 5; c++) {
            const letter = matrix[r][c];
            const isKeyLetter = cleanKeyChars.has(letter);
            tableHtml += `<td class="polybius-cell ${isKeyLetter ? 'key-letter' : ''}" title="Row ${r}, Col ${c}">${letter === 'I' ? 'I/J' : letter}</td>`;
          }
          tableHtml += '</tr>';
        }
        tableHtml += '</table>';
        DOM.matrixDisplay.innerHTML = tableHtml;
      };

      input.addEventListener('input', () => {
        input.value = input.value.toUpperCase();
        updatePlayfairVisual();
      });
      updatePlayfairVisual();
      break;
    }

    case 'hill': {
      DOM.keyHelpHint.textContent = '2×2 integer key matrix modulo 26: [k00, k01; k10, k11]';
      const container = document.createElement('div');
      container.className = 'key-input-row';
      container.innerHTML = `
        <div class="matrix-input-grid">
          <div class="matrix-cell-group">
            <label class="matrix-cell-label" for="hill-00">k₀₀ (Row 0, Col 0)</label>
            <input type="number" id="hill-00" class="cyber-input matrix-cell-input" value="3">
          </div>
          <div class="matrix-cell-group">
            <label class="matrix-cell-label" for="hill-01">k₀₁ (Row 0, Col 1)</label>
            <input type="number" id="hill-01" class="cyber-input matrix-cell-input" value="3">
          </div>
          <div class="matrix-cell-group">
            <label class="matrix-cell-label" for="hill-10">k₁₀ (Row 1, Col 0)</label>
            <input type="number" id="hill-10" class="cyber-input matrix-cell-input" value="2">
          </div>
          <div class="matrix-cell-group">
            <label class="matrix-cell-label" for="hill-11">k₁₁ (Row 1, Col 1)</label>
            <input type="number" id="hill-11" class="cyber-input matrix-cell-input" value="5">
          </div>
        </div>
        <div class="matrix-info-badge" id="hill-status-badge">
          <span>Determinant: <strong id="hill-det-val">9</strong></span>
          <span>Coprime with 26: <strong id="hill-coprime-val" class="text-neon">YES (gcd=1)</strong></span>
          <span>Inverse det⁻¹ mod 26: <strong id="hill-detinv-val">3</strong></span>
        </div>
      `;
      DOM.dynamicKeyContainer.appendChild(container);

      // Preset button
      const presetBtn = document.createElement('button');
      presetBtn.type = 'button';
      presetBtn.className = 'btn btn-secondary btn-sm';
      presetBtn.textContent = 'Preset [3, 3; 2, 5]';
      presetBtn.addEventListener('click', () => {
        document.getElementById('hill-00').value = 3;
        document.getElementById('hill-01').value = 3;
        document.getElementById('hill-10').value = 2;
        document.getElementById('hill-11').value = 5;
        updateHillVisual();
      });
      DOM.keyToolbar.appendChild(presetBtn);

      const altPresetBtn = document.createElement('button');
      altPresetBtn.type = 'button';
      altPresetBtn.className = 'btn btn-ghost btn-sm';
      altPresetBtn.textContent = 'Preset [5, 8; 17, 3]';
      altPresetBtn.addEventListener('click', () => {
        document.getElementById('hill-00').value = 5;
        document.getElementById('hill-01').value = 8;
        document.getElementById('hill-10').value = 17;
        document.getElementById('hill-11').value = 3;
        updateHillVisual();
      });
      DOM.keyToolbar.appendChild(altPresetBtn);

      const updateHillVisual = () => {
        const k00 = parseInt(document.getElementById('hill-00').value, 10) || 0;
        const k01 = parseInt(document.getElementById('hill-01').value, 10) || 0;
        const k10 = parseInt(document.getElementById('hill-10').value, 10) || 0;
        const k11 = parseInt(document.getElementById('hill-11').value, 10) || 0;

        const val = validateHillKey2x2(k00, k01, k10, k11);
        const detVal = document.getElementById('hill-det-val');
        const coprimeVal = document.getElementById('hill-coprime-val');
        const detInvVal = document.getElementById('hill-detinv-val');

        if (val.valid) {
          detVal.textContent = val.det;
          coprimeVal.textContent = 'YES (gcd=1)';
          coprimeVal.className = 'text-neon';
          detInvVal.textContent = val.detInv;
          setValidationMessage('');
        } else {
          detVal.textContent = val.det;
          coprimeVal.textContent = 'NO (INVALID)';
          coprimeVal.className = 'text-error';
          detInvVal.textContent = 'None';
          setValidationMessage(val.error, 'error');
        }
      };

      container.querySelectorAll('input').forEach(inp => {
        inp.addEventListener('input', updateHillVisual);
      });
      updateHillVisual();
      break;
    }

    case 'vigenere': {
      DOM.keyHelpHint.textContent = 'Alphabetic keyword (e.g., LEMON, CIPHER)';
      const input = document.createElement('input');
      input.type = 'text';
      input.id = 'vigenere-key-input';
      input.className = 'cyber-input';
      input.value = 'LEMON';
      input.placeholder = 'Enter keyword...';
      input.setAttribute('aria-label', 'Vigenère keyword');
      DOM.dynamicKeyContainer.appendChild(input);

      input.addEventListener('input', () => {
        input.value = input.value.toUpperCase();
        if (!cleanAlphaOnly(input.value)) {
          setValidationMessage('Keyword must contain at least one alphabetic letter.', 'warning');
        } else {
          setValidationMessage('');
        }
      });
      break;
    }

    case 'otp': {
      DOM.keyHelpHint.textContent = 'One-Time Pad key (must be at least as long as text letters)';
      const input = document.createElement('input');
      input.type = 'text';
      input.id = 'otp-key-input';
      input.className = 'cyber-input';
      input.value = 'SECRETKEYFORONETIMEPADVERIFICATION2027';
      input.placeholder = 'Enter random key...';
      input.setAttribute('aria-label', 'One-time pad key');
      DOM.dynamicKeyContainer.appendChild(input);

      const randOtpBtn = document.createElement('button');
      randOtpBtn.type = 'button';
      randOtpBtn.className = 'btn btn-secondary btn-sm';
      randOtpBtn.innerHTML = `
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
        Generate Random Pad
      `;
      randOtpBtn.addEventListener('click', () => {
        const textLen = Math.max(32, cleanAlphaOnly(DOM.textInput.value).length);
        const pad = generateRandomAlphabetString(textLen);
        input.value = pad;
        showToast(`Generated ${textLen}-character random One-Time Pad key.`, 'info');
        setValidationMessage('');
      });
      DOM.keyToolbar.appendChild(randOtpBtn);

      input.addEventListener('input', () => {
        input.value = input.value.toUpperCase();
        checkOtpKeyLength();
      });
      break;
    }

    case 'railfence': {
      DOM.keyHelpHint.textContent = 'Number of zigzag parallel rails (integer ≥ 2)';
      const row = document.createElement('div');
      row.className = 'key-input-row';
      row.innerHTML = `
        <input type="number" id="railfence-input" class="cyber-input" min="2" max="20" value="3" style="width: 120px;" aria-label="Rail fence rails count">
        <span class="input-hint">Trajectory cycles every 2×(Rails - 1) positions</span>
      `;
      DOM.dynamicKeyContainer.appendChild(row);

      const inp = row.querySelector('#railfence-input');
      inp.addEventListener('input', () => {
        const val = parseInt(inp.value, 10);
        if (isNaN(val) || val < 2) {
          setValidationMessage('Rail count must be an integer ≥ 2.', 'error');
        } else {
          setValidationMessage('');
        }
      });
      break;
    }

    case 'columnar': {
      DOM.keyHelpHint.textContent = 'Keyword for column sorting (e.g., GERMAN, SECRET)';
      const input = document.createElement('input');
      input.type = 'text';
      input.id = 'columnar-key-input';
      input.className = 'cyber-input';
      input.value = 'GERMAN';
      input.placeholder = 'Enter keyword...';
      input.setAttribute('aria-label', 'Columnar keyword');
      DOM.dynamicKeyContainer.appendChild(input);

      DOM.visualMatrixPanel.classList.remove('hidden');
      DOM.matrixTitleText.textContent = 'COLUMN ORDER INSPECTION';
      DOM.matrixStatusTag.textContent = 'Alphabetical Rank Permutation';

      const updateColumnarVisual = () => {
        try {
          const { readOrder, cleanKey } = getColumnarOrder(input.value);
          let badgesHtml = '<div style="display:flex;gap:8px;flex-wrap:wrap;justify-content:center;">';
          for (let i = 0; i < cleanKey.length; i++) {
            const rank = readOrder.indexOf(i) + 1;
            badgesHtml += `
              <div style="background:var(--bg-secondary);border:1px solid var(--border-cyan);padding:6px 10px;border-radius:6px;text-align:center;">
                <div style="font-size:0.75rem;color:var(--text-secondary);">Col ${i}</div>
                <div style="font-weight:700;color:var(--neon-green);font-size:1.1rem;">${cleanKey[i]}</div>
                <div style="font-size:0.7rem;color:var(--neon-cyan);">Rank ${rank}</div>
              </div>
            `;
          }
          badgesHtml += '</div>';
          DOM.matrixDisplay.innerHTML = badgesHtml;
          setValidationMessage('');
        } catch (err) {
          DOM.matrixDisplay.innerHTML = '';
          setValidationMessage(err.message, 'warning');
        }
      };

      input.addEventListener('input', () => {
        input.value = input.value.toUpperCase();
        updateColumnarVisual();
      });
      updateColumnarVisual();
      break;
    }
  }
}

function validateMonoKeyInput(key) {
  const res = validateMonoKey(key);
  if (!res.valid) {
    setValidationMessage(res.error, 'error');
  } else {
    setValidationMessage('');
  }
}

function checkOtpKeyLength() {
  const otpInput = document.getElementById('otp-key-input');
  if (!otpInput) return;
  const cleanKey = cleanAlphaOnly(otpInput.value);
  const textChars = cleanAlphaOnly(DOM.textInput.value).length;
  if (textChars > 0 && cleanKey.length < textChars) {
    setValidationMessage(`Warning: OTP key (${cleanKey.length} chars) is shorter than plaintext alphabetic characters (${textChars}).`, 'error');
  } else {
    setValidationMessage('');
  }
}

/**
 * Returns key arguments according to selected cipher
 */
function getActiveCipherKey() {
  const cipher = AppState.currentCipher;
  switch (cipher) {
    case 'caesar': {
      const num = document.getElementById('caesar-num');
      return parseInt(num ? num.value : 3, 10);
    }
    case 'monoalphabetic': {
      const input = document.getElementById('mono-key-input');
      return input ? input.value : 'QWERTYUIOPASDFGHJKLZXCVBNM';
    }
    case 'playfair': {
      const input = document.getElementById('playfair-key-input');
      return input ? input.value : 'MONARCHY';
    }
    case 'hill': {
      return {
        k00: document.getElementById('hill-00') ? document.getElementById('hill-00').value : 3,
        k01: document.getElementById('hill-01') ? document.getElementById('hill-01').value : 3,
        k10: document.getElementById('hill-10') ? document.getElementById('hill-10').value : 2,
        k11: document.getElementById('hill-11') ? document.getElementById('hill-11').value : 5
      };
    }
    case 'vigenere': {
      const input = document.getElementById('vigenere-key-input');
      return input ? input.value : 'LEMON';
    }
    case 'otp': {
      const input = document.getElementById('otp-key-input');
      return input ? input.value : '';
    }
    case 'railfence': {
      const input = document.getElementById('railfence-input');
      return parseInt(input ? input.value : 3, 10);
    }
    case 'columnar': {
      const input = document.getElementById('columnar-key-input');
      return input ? input.value : 'GERMAN';
    }
    default:
      return null;
  }
}

/**
 * Executes active cipher encryption or decryption
 */
function executeActiveCipher() {
  const cipherId = AppState.currentCipher;
  const mode = AppState.currentMode;
  const text = DOM.textInput.value;

  if (text.trim() === '') {
    showToast('Input text buffer is empty. Please enter text to process.', 'error');
    DOM.textInput.focus();
    return;
  }

  const key = getActiveCipherKey();
  let result = '';
  let duration = 0;

  try {
    const startTime = performance.now();

    if (cipherId === 'caesar') {
      result = mode === 'encrypt' ? caesarEncrypt(text, key) : caesarDecrypt(text, key);
    } else if (cipherId === 'monoalphabetic') {
      result = mode === 'encrypt' ? monoalphabeticEncrypt(text, key) : monoalphabeticDecrypt(text, key);
    } else if (cipherId === 'playfair') {
      result = mode === 'encrypt' ? playfairEncrypt(text, key) : playfairDecrypt(text, key);
    } else if (cipherId === 'hill') {
      result = mode === 'encrypt' 
        ? hillEncrypt(text, key.k00, key.k01, key.k10, key.k11)
        : hillDecrypt(text, key.k00, key.k01, key.k10, key.k11);
    } else if (cipherId === 'vigenere') {
      result = mode === 'encrypt' ? vigenereEncrypt(text, key) : vigenereDecrypt(text, key);
    } else if (cipherId === 'otp') {
      result = mode === 'encrypt' ? otpEncrypt(text, key) : otpDecrypt(text, key);
    } else if (cipherId === 'railfence') {
      result = mode === 'encrypt' ? railFenceEncrypt(text, key) : railFenceDecrypt(text, key);
    } else if (cipherId === 'columnar') {
      result = mode === 'encrypt' ? columnarEncrypt(text, key) : columnarDecrypt(text, key);
    }

    const endTime = performance.now();
    duration = endTime - startTime;

    AppState.lastExecutionResult = result;
    DOM.outputDisplay.textContent = result;
    DOM.outputCharCount.textContent = result.length;
    DOM.execTimeBadge.textContent = `⏱ ${duration.toFixed(2)} ms`;
    DOM.terminalSessionTitle.textContent = `SESSION: ${CIPHER_REGISTRY[cipherId].name.toUpperCase()} // ${mode.toUpperCase()} SUCCESS`;

    setValidationMessage('');
    showToast(`${CIPHER_REGISTRY[cipherId].name} ${mode} completed in ${duration.toFixed(2)} ms`, 'success');

  } catch (err) {
    setValidationMessage(err.message, 'error');
    showToast(err.message, 'error');
    DOM.terminalSessionTitle.textContent = `SESSION: ${CIPHER_REGISTRY[cipherId].name.toUpperCase()} // ERROR`;
  }
}

/**
 * Updates UI to reflect newly selected cipher
 */
function selectCipher(cipherId) {
  if (!CIPHER_REGISTRY[cipherId]) return;
  AppState.currentCipher = cipherId;
  const info = CIPHER_REGISTRY[cipherId];

  // Update card active states
  document.querySelectorAll('.cipher-card').forEach(card => {
    const isSelected = card.getAttribute('data-cipher') === cipherId;
    card.classList.toggle('active', isSelected);
    card.setAttribute('aria-checked', isSelected ? 'true' : 'false');
  });

  // Update banner info
  DOM.activeCipherTitle.textContent = info.name;
  DOM.activeFamilyTag.textContent = info.familyLabel;
  DOM.activeFamilyTag.className = `cipher-family-badge ${info.family === 'substitution' ? 'badge-sub' : 'badge-trans'}`;
  DOM.activeCipherFormula.textContent = `Model: ${info.formula}`;
  DOM.activeCipherDesc.textContent = info.desc;
  DOM.terminalSessionTitle.textContent = `SESSION: ${info.name.toUpperCase()} // BUFFER READY`;

  // Render specific key fields
  renderDynamicKeyControls(cipherId);
}

/**
 * Switches between Encrypt and Decrypt mode
 */
function setMode(mode) {
  AppState.currentMode = mode;
  const isEncrypt = mode === 'encrypt';

  DOM.modeEncrypt.classList.toggle('active', isEncrypt);
  DOM.modeEncrypt.setAttribute('aria-checked', isEncrypt ? 'true' : 'false');
  DOM.modeDecrypt.classList.toggle('active', !isEncrypt);
  DOM.modeDecrypt.setAttribute('aria-checked', !isEncrypt ? 'true' : 'false');

  DOM.executeBtnLabel.textContent = isEncrypt ? 'EXECUTE ENCRYPTION' : 'EXECUTE DECRYPTION';
  document.getElementById('input-label-text').querySelector('.label-indicator').textContent = 
    isEncrypt ? 'INPUT PLAINTEXT' : 'INPUT CIPHERTEXT';
  document.getElementById('output-mode-hint').textContent = 
    isEncrypt ? 'CIPHERTEXT TERMINAL' : 'PLAINTEXT TERMINAL';

  DOM.textInput.placeholder = isEncrypt 
    ? 'Enter plaintext to encrypt or click "Load Sample Text" above...' 
    : 'Enter ciphertext to decrypt...';
}

/**
 * Updates input character and word counters
 */
function updateInputCounters() {
  const text = DOM.textInput.value;
  DOM.inputCharCount.textContent = text.length;
  const words = text.trim() ? text.trim().split(/\s+/).length : 0;
  DOM.inputWordCount.textContent = words;
  checkOtpKeyLength();
}

/**
 * Copies output text to clipboard with fallback
 */
function copyOutputToClipboard() {
  const text = AppState.lastExecutionResult;
  if (!text) {
    showToast('No output text available to copy.', 'error');
    return;
  }

  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(() => {
      showToast('Output copied to clipboard!', 'success');
    }).catch(() => {
      fallbackCopyText(text);
    });
  } else {
    fallbackCopyText(text);
  }
}

function fallbackCopyText(text) {
  const textArea = document.createElement('textarea');
  textArea.value = text;
  textArea.style.position = 'fixed';
  textArea.style.opacity = '0';
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  try {
    const successful = document.execCommand('copy');
    if (successful) {
      showToast('Output copied to clipboard!', 'success');
    } else {
      showToast('Unable to copy automatically. Please select text manually.', 'error');
    }
  } catch (err) {
    showToast('Clipboard access denied.', 'error');
  }
  document.body.removeChild(textArea);
}

/**
 * Downloads output as a .txt file
 */
function downloadOutput() {
  const text = AppState.lastExecutionResult;
  if (!text) {
    showToast('No output to download.', 'error');
    return;
  }

  const cipherName = CIPHER_REGISTRY[AppState.currentCipher].id;
  const mode = AppState.currentMode;
  const filename = `cryptocore_${cipherName}_${mode}_${Date.now()}.txt`;

  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showToast(`Downloaded: ${filename}`, 'info');
}

/**
 * Swaps output back to input for reverse processing
 */
function swapInputOutput() {
  if (!AppState.lastExecutionResult) {
    showToast('Output is empty. Cannot swap.', 'warning');
    return;
  }

  const outputVal = AppState.lastExecutionResult;
  DOM.textInput.value = outputVal;
  updateInputCounters();

  // Toggle mode
  setMode(AppState.currentMode === 'encrypt' ? 'decrypt' : 'encrypt');
  showToast('Swapped output into input buffer and toggled mode.', 'info');
}

/**
 * Clears input and output buffers
 */
function clearBuffers() {
  DOM.textInput.value = '';
  DOM.outputDisplay.innerHTML = '<span class="output-placeholder">// Cryptographic output will appear here after execution...</span>';
  AppState.lastExecutionResult = '';
  DOM.outputCharCount.textContent = '0';
  DOM.execTimeBadge.textContent = '⏱ 0.00 ms';
  updateInputCounters();
  setValidationMessage('');
  showToast('Buffers cleared.', 'info');
}

/* ==========================================================================
   7. ALGORITHM COMPARISON MODULE
   ========================================================================== */

const COMPARISON_VULNERABILITIES = {
  caesar: 'Extremely vulnerable. Keyspace is only 25; trivially broken by brute-force search or letter frequency analysis in < 1 ms.',
  monoalphabetic: 'Vulnerable. Keyspace is 26! ≈ 4×10²⁶, yet vulnerable to single-letter & digraph frequency analysis (e.g. E, T, A).',
  playfair: 'Vulnerable. Flattens single-letter frequencies by using digraphs, but susceptible to digraph frequency analysis & known-plaintext.',
  hill: 'Vulnerable to Known-Plaintext Attack (KPA). Requires only 2 known plaintext-ciphertext digraph pairs to solve key matrix via linear algebra.',
  vigenere: 'Vulnerable to Kasiski examination and Friedman Index of Coincidence (IoC) to determine key length, followed by Caesar frequency solving.',
  otp: 'Unconditionally secure IF key is truly random, never reused, kept secret, and ≥ message length. Vulnerable if key is reused (Two-Time Pad).',
  railfence: 'Vulnerable. Transposition preserves character frequencies; trivially broken by testing small rail counts (2 to 20).',
  columnar: 'Vulnerable. Preserves letter frequencies; broken through anagramming methods and known-word structural reconstruction.'
};

function runAlgorithmComparison() {
  const text = DOM.compareTextInput.value;
  if (!text.trim()) {
    showToast('Please provide text to benchmark.', 'error');
    DOM.compareTextInput.focus();
    return;
  }

  DOM.comparisonTbody.innerHTML = '';
  const ciphers = Object.values(CIPHER_REGISTRY);

  ciphers.forEach(cipher => {
    let keyUsed = '';
    let duration = 0;
    let preview = '';
    let statusHtml = '';

    try {
      const start = performance.now();
      let ciphertext = '';

      if (cipher.id === 'caesar') {
        keyUsed = 'Shift = 5';
        ciphertext = caesarEncrypt(text, 5);
      } else if (cipher.id === 'monoalphabetic') {
        keyUsed = 'Standard QWERTY... Permutation';
        ciphertext = monoalphabeticEncrypt(text, 'QWERTYUIOPASDFGHJKLZXCVBNM');
      } else if (cipher.id === 'playfair') {
        keyUsed = 'MONARCHY';
        ciphertext = playfairEncrypt(text, 'MONARCHY');
      } else if (cipher.id === 'hill') {
        keyUsed = '[3, 3; 2, 5] (det=9)';
        ciphertext = hillEncrypt(text, 3, 3, 2, 5);
      } else if (cipher.id === 'vigenere') {
        keyUsed = 'SECURITY';
        ciphertext = vigenereEncrypt(text, 'SECURITY');
      } else if (cipher.id === 'otp') {
        const lettersCount = cleanAlphaOnly(text).length;
        const padKey = generateRandomAlphabetString(Math.max(lettersCount, 32));
        keyUsed = `Random Pad (${padKey.slice(0, 8)}...)`;
        ciphertext = otpEncrypt(text, padKey);
      } else if (cipher.id === 'railfence') {
        keyUsed = 'Rails = 3';
        ciphertext = railFenceEncrypt(text, 3);
      } else if (cipher.id === 'columnar') {
        keyUsed = 'CIPHER';
        ciphertext = columnarEncrypt(text, 'CIPHER');
      }

      const end = performance.now();
      duration = end - start;
      preview = ciphertext.length > 32 ? ciphertext.slice(0, 32) + '...' : ciphertext;
      statusHtml = '<span class="test-badge pass">SUCCESS</span>';

    } catch (err) {
      preview = err.message;
      statusHtml = '<span class="test-badge fail">ERROR</span>';
    }

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="table-cipher-name">${cipher.name}</span></td>
      <td><span class="cipher-family-badge ${cipher.family === 'substitution' ? 'badge-sub' : 'badge-trans'}">${cipher.familyLabel}</span></td>
      <td><code>${keyUsed}</code></td>
      <td><span class="table-time">${duration.toFixed(2)} ms</span></td>
      <td><span class="table-preview" title="${escapeHtml(preview)}">${escapeHtml(preview)}</span></td>
      <td>${statusHtml}</td>
      <td><span class="table-vulnerability">${COMPARISON_VULNERABILITIES[cipher.id]}</span></td>
    `;
    DOM.comparisonTbody.appendChild(tr);
  });

  showToast('Algorithm comparison completed across all 8 classical ciphers.', 'success');
}

function escapeHtml(str) {
  return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/* ==========================================================================
   8. CLIENT-SIDE FILE TOOLS MODULE
   ========================================================================== */

function initFileTools() {
  // Drag & drop handlers
  ['dragenter', 'dragover'].forEach(eventName => {
    DOM.fileDropZone.addEventListener(eventName, e => {
      e.preventDefault();
      DOM.fileDropZone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    DOM.fileDropZone.addEventListener(eventName, e => {
      e.preventDefault();
      DOM.fileDropZone.classList.remove('dragover');
    });
  });

  DOM.fileDropZone.addEventListener('drop', e => {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleFileSelected(files[0]);
    }
  });

  DOM.browseFileBtn.addEventListener('click', () => {
    DOM.fileInput.click();
  });

  DOM.fileInput.addEventListener('change', e => {
    if (e.target.files.length > 0) {
      handleFileSelected(e.target.files[0]);
    }
  });

  // Cipher dropdown change updates hint
  DOM.fileCipherSelect.addEventListener('change', e => {
    updateFileKeyHints(e.target.value);
  });

  DOM.fileEncryptBtn.addEventListener('click', () => processFile(true));
  DOM.fileDecryptBtn.addEventListener('click', () => processFile(false));
  DOM.fileDownloadBtn.addEventListener('click', downloadProcessedFile);

  updateFileKeyHints(DOM.fileCipherSelect.value);
}

function updateFileKeyHints(cipher) {
  const label = document.getElementById('file-key-label');
  const hint = document.getElementById('file-key-hint');
  const input = DOM.fileKeyInput;

  switch (cipher) {
    case 'caesar':
      label.textContent = 'Shift Key (0-25)';
      hint.textContent = 'Integer shift from 0 to 25';
      input.value = '3';
      break;
    case 'monoalphabetic':
      label.textContent = '26-Letter Alphabet';
      hint.textContent = 'Unique 26-letter substitution alphabet';
      input.value = 'QWERTYUIOPASDFGHJKLZXCVBNM';
      break;
    case 'playfair':
      label.textContent = 'Playfair Keyword';
      hint.textContent = 'Keyword for 5x5 matrix';
      input.value = 'MONARCHY';
      break;
    case 'hill':
      label.textContent = '2x2 Matrix: k00,k01,k10,k11';
      hint.textContent = 'Comma-separated 4 integers (e.g. 3,3,2,5)';
      input.value = '3,3,2,5';
      break;
    case 'vigenere':
      label.textContent = 'Vigenère Keyword';
      hint.textContent = 'Alphabetic keyword (e.g. CIPHER)';
      input.value = 'CIPHERKEY';
      break;
    case 'otp':
      label.textContent = 'One-Time Pad Key';
      hint.textContent = 'Letters key at least as long as file alphabetic letters';
      input.value = 'VERYLONGSECRETKEYEXCEEDINGFILELENGTH2027';
      break;
    case 'railfence':
      label.textContent = 'Rail Count (≥ 2)';
      hint.textContent = 'Integer number of parallel rails';
      input.value = '3';
      break;
    case 'columnar':
      label.textContent = 'Columnar Keyword';
      hint.textContent = 'Keyword for column sorting (e.g. GERMAN)';
      input.value = 'GERMAN';
      break;
  }
}

function handleFileSelected(file) {
  if (!file) return;

  if (!file.name.endsWith('.txt') && file.type && !file.type.includes('text')) {
    showToast('Please select a plain text (.txt) file.', 'error');
    return;
  }

  // Max 500 KB limit for safe browser-side manipulation
  if (file.size > 500 * 1024) {
    showToast('File size exceeds 500 KB. Classical ciphers are intended for demonstration.', 'warning');
  }

  const reader = new FileReader();
  reader.onload = e => {
    const content = e.target.result;
    AppState.fileData.name = file.name;
    AppState.fileData.size = file.size;
    AppState.fileData.text = content;
    AppState.fileData.processedText = '';

    DOM.fileMetaCard.classList.remove('hidden');
    DOM.fileNameVal.textContent = file.name;
    DOM.fileSizeVal.textContent = `${(file.size / 1024).toFixed(2)} KB`;
    DOM.fileCharsVal.textContent = content.length.toLocaleString();

    DOM.filePreviewText.value = content.slice(0, 1500) + (content.length > 1500 ? '\n... [Preview truncated]' : '');
    DOM.fileResultPreview.value = '';
    DOM.fileDownloadBtn.disabled = true;

    showToast(`Loaded "${file.name}" into local memory.`, 'success');
  };

  reader.onerror = () => {
    showToast('Error reading local file.', 'error');
  };

  reader.readAsText(file);
}

function processFile(isEncrypt) {
  if (!AppState.fileData.text) {
    showToast('Please upload or select a text file first.', 'error');
    return;
  }

  const cipher = DOM.fileCipherSelect.value;
  const rawKey = DOM.fileKeyInput.value.trim();
  const text = AppState.fileData.text;

  let result = '';
  let duration = 0;

  try {
    const start = performance.now();

    if (cipher === 'caesar') {
      const shift = parseInt(rawKey, 10) || 0;
      result = isEncrypt ? caesarEncrypt(text, shift) : caesarDecrypt(text, shift);
    } else if (cipher === 'monoalphabetic') {
      result = isEncrypt ? monoalphabeticEncrypt(text, rawKey) : monoalphabeticDecrypt(text, rawKey);
    } else if (cipher === 'playfair') {
      result = isEncrypt ? playfairEncrypt(text, rawKey) : playfairDecrypt(text, rawKey);
    } else if (cipher === 'hill') {
      const parts = rawKey.split(',').map(s => parseInt(s.trim(), 10));
      if (parts.length !== 4) throw new Error('Hill cipher key must be 4 comma-separated numbers (k00,k01,k10,k11).');
      result = isEncrypt 
        ? hillEncrypt(text, parts[0], parts[1], parts[2], parts[3])
        : hillDecrypt(text, parts[0], parts[1], parts[2], parts[3]);
    } else if (cipher === 'vigenere') {
      result = isEncrypt ? vigenereEncrypt(text, rawKey) : vigenereDecrypt(text, rawKey);
    } else if (cipher === 'otp') {
      result = isEncrypt ? otpEncrypt(text, rawKey) : otpDecrypt(text, rawKey);
    } else if (cipher === 'railfence') {
      const rails = parseInt(rawKey, 10);
      result = isEncrypt ? railFenceEncrypt(text, rails) : railFenceDecrypt(text, rails);
    } else if (cipher === 'columnar') {
      result = isEncrypt ? columnarEncrypt(text, rawKey) : columnarDecrypt(text, rawKey);
    }

    const end = performance.now();
    duration = end - start;

    AppState.fileData.processedText = result;
    DOM.fileResultPreview.value = result.slice(0, 1500) + (result.length > 1500 ? '\n... [Preview truncated]' : '');
    DOM.fileExecTime.textContent = `⏱ ${duration.toFixed(2)} ms`;
    DOM.fileDownloadBtn.disabled = false;

    showToast(`File ${isEncrypt ? 'encrypted' : 'decrypted'} successfully in ${duration.toFixed(2)} ms!`, 'success');

  } catch (err) {
    showToast(`File processing error: ${err.message}`, 'error');
  }
}

function downloadProcessedFile() {
  if (!AppState.fileData.processedText) {
    showToast('No processed file data to download.', 'error');
    return;
  }

  const origName = AppState.fileData.name || 'document.txt';
  const baseName = origName.replace(/\.[^/.]+$/, '');
  const cipher = DOM.fileCipherSelect.value;
  const outName = `${baseName}_${cipher}_processed.txt`;

  const blob = new Blob([AppState.fileData.processedText], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = outName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showToast(`Downloaded: ${outName}`, 'info');
}

/* ==========================================================================
   9. AUTOMATED SELF-TEST & VERIFICATION HARNESS
   ========================================================================== */

const SELF_TEST_SUITE = [
  {
    id: 'test-caesar',
    name: 'Caesar Cipher Test Vector & Invertibility',
    description: 'ABC with shift 3 → DEF, and inverse restores ABC.',
    run: () => {
      const enc = caesarEncrypt('ABC', 3);
      if (enc !== 'DEF') throw new Error(`Expected 'DEF', got '${enc}'`);
      const dec = caesarDecrypt(enc, 3);
      if (dec !== 'ABC') throw new Error(`Decryption failed: expected 'ABC', got '${dec}'`);
      return `Passed: ABC -> DEF -> ABC`;
    }
  },
  {
    id: 'test-vigenere',
    name: 'Vigenère Cipher Reference Vector',
    description: 'ATTACKATDAWN with key LEMON → LXFOPVEFRNHR.',
    run: () => {
      const enc = vigenereEncrypt('ATTACKATDAWN', 'LEMON');
      if (enc !== 'LXFOPVEFRNHR') throw new Error(`Expected 'LXFOPVEFRNHR', got '${enc}'`);
      const dec = vigenereDecrypt(enc, 'LEMON');
      if (dec !== 'ATTACKATDAWN') throw new Error(`Decryption failed: expected 'ATTACKATDAWN', got '${dec}'`);
      return `Passed: ATTACKATDAWN -> LXFOPVEFRNHR -> ATTACKATDAWN`;
    }
  },
  {
    id: 'test-playfair',
    name: 'Playfair Cipher Reference & Digraph Rules',
    description: 'INSTRUMENTS with key MONARCHY → GATLMZCLRQXA and roundtrip.',
    run: () => {
      const enc = playfairEncrypt('INSTRUMENTS', 'MONARCHY');
      if (enc !== 'GATLMZCLRQXA') throw new Error(`Expected 'GATLMZCLRQXA', got '${enc}'`);
      const dec = playfairDecrypt(enc, 'MONARCHY');
      // Filler X at end produces INSTRUMENTSX
      if (!dec.startsWith('INSTRUMENTS')) throw new Error(`Decryption failed: expected prefix 'INSTRUMENTS', got '${dec}'`);
      return `Passed: INSTRUMENTS -> GATLMZCLRQXA -> ${dec}`;
    }
  },
  {
    id: 'test-hill-invertible',
    name: 'Hill Cipher 2×2 Invertibility Test',
    description: 'Invertible matrix [3, 3; 2, 5] (det=9, det⁻¹=3 mod 26) with HELP.',
    run: () => {
      const enc = hillEncrypt('HELP', 3, 3, 2, 5);
      const dec = hillDecrypt(enc, 3, 3, 2, 5);
      if (dec !== 'HELP') throw new Error(`Hill roundtrip failed: expected 'HELP', got '${dec}'`);
      return `Passed: HELP -> ${enc} -> HELP`;
    }
  },
  {
    id: 'test-hill-reject',
    name: 'Hill Cipher Noninvertible Matrix Rejection',
    description: 'Rejection of non-invertible matrix [2, 4; 1, 2] (det=0, gcd=26).',
    run: () => {
      const val = validateHillKey2x2(2, 4, 1, 2);
      if (val.valid) throw new Error('Failed: Expected non-invertible matrix to be rejected.');
      return `Passed: Correctly rejected non-invertible matrix (gcd=${gcd(val.det, 26)})`;
    }
  },
  {
    id: 'test-railfence',
    name: 'Rail Fence Cipher Reference Vector',
    description: 'WEAREDISCOVEREDFLEEATONCE on 3 rails → WECRLTEERDSOEEFEAOCAIVDEN.',
    run: () => {
      const text = 'WEAREDISCOVEREDFLEEATONCE';
      const enc = railFenceEncrypt(text, 3);
      if (enc !== 'WECRLTEERDSOEEFEAOCAIVDEN') {
        throw new Error(`Expected 'WECRLTEERDSOEEFEAOCAIVDEN', got '${enc}'`);
      }
      const dec = railFenceDecrypt(enc, 3);
      if (dec !== text) throw new Error(`Rail fence roundtrip failed: got '${dec}'`);
      return `Passed: ${text} -> ${enc} -> ${dec}`;
    }
  },
  {
    id: 'test-monoalphabetic',
    name: 'Monoalphabetic Substitution Bijective Roundtrip',
    description: 'Validates 26-unique-letter permutation and full reverse mapping.',
    run: () => {
      const key = 'QWERTYUIOPASDFGHJKLZXCVBNM';
      const text = 'The Quick Brown Fox Jumps Over 13 Lazy Dogs!';
      const enc = monoalphabeticEncrypt(text, key);
      const dec = monoalphabeticDecrypt(enc, key);
      if (dec !== text) throw new Error(`Monoalphabetic roundtrip failed: got '${dec}'`);
      return `Passed: Preserved case, punctuation, numbers across full roundtrip.`;
    }
  },
  {
    id: 'test-otp',
    name: 'One-Time Pad Modulo-26 & Length Rejection',
    description: 'Modulo-26 encryption/decryption & strict short-key rejection.',
    run: () => {
      const text = 'NETWORK SECURITY';
      const key = 'SECRETKEYFORONETIMEPADVERIFICATION2027';
      const enc = otpEncrypt(text, key);
      const dec = otpDecrypt(enc, key);
      if (dec !== text) throw new Error(`OTP roundtrip failed: got '${dec}'`);

      // Verify short key rejection
      let rejected = false;
      try {
        otpEncrypt('LONGMESSAGE', 'SHORT');
      } catch (e) {
        rejected = true;
      }
      if (!rejected) throw new Error('OTP failed to reject key shorter than message.');
      return `Passed: Verified roundtrip and strict Shannon key length constraint.`;
    }
  },
  {
    id: 'test-columnar-unique',
    name: 'Columnar Transposition (Unique Key)',
    description: 'Validates permutation and lossless roundtrip with unique key ZEBRA.',
    run: () => {
      const text = 'NETWORK SECURITY PROTOCOLS 2027';
      const key = 'ZEBRA';
      const enc = columnarEncrypt(text, key);
      const dec = columnarDecrypt(enc, key);
      if (dec !== text) throw new Error(`Columnar unique key roundtrip failed: got '${dec}'`);
      return `Passed: Roundtrip lossless with unique key '${key}'.`;
    }
  },
  {
    id: 'test-columnar-repeated',
    name: 'Columnar Transposition (Repeated-Letter Key)',
    description: 'Validates stable index sorting and roundtrip with repeated-letter key SECRET.',
    run: () => {
      const text = 'DEFEND THE EAST WALL AT DAWN';
      const key = 'SECRET';
      const enc = columnarEncrypt(text, key);
      const dec = columnarDecrypt(enc, key);
      if (dec !== text) throw new Error(`Columnar repeated key roundtrip failed: got '${dec}'`);
      return `Passed: Roundtrip lossless with duplicate letters in '${key}'.`;
    }
  },
  {
    id: 'test-sample-demo',
    name: 'Academic Sample Demo: NETWORK SECURITY with Caesar (k=5)',
    description: 'Calculates standard Caesar shift 5 on NETWORK SECURITY programmatically.',
    run: () => {
      const text = 'NETWORK SECURITY';
      const enc = caesarEncrypt(text, 5);
      const expected = 'SJYBTWP XJHZWNYD';
      if (enc !== expected) throw new Error(`Expected '${expected}', got '${enc}'`);
      const dec = caesarDecrypt(enc, 5);
      if (dec !== text) throw new Error(`Decryption failed: expected '${text}', got '${dec}'`);
      return `Passed: NETWORK SECURITY -> ${enc} -> ${dec}`;
    }
  }
];

function runAllSelfTests() {
  DOM.testResultsList.innerHTML = '';
  let passCount = 0;
  const startTime = performance.now();

  SELF_TEST_SUITE.forEach(test => {
    let passed = false;
    let detail = '';

    try {
      detail = test.run();
      passed = true;
      passCount++;
    } catch (err) {
      detail = err.message;
      passed = false;
    }

    const card = document.createElement('div');
    card.className = 'test-item-card';
    card.innerHTML = `
      <div class="test-info-col">
        <div class="test-title-row">
          <span class="test-name">${test.name}</span>
          <span class="test-badge ${passed ? 'pass' : 'fail'}">${passed ? 'PASS' : 'FAIL'}</span>
        </div>
        <div class="test-vector-desc">${test.description}</div>
        <div style="font-family:var(--font-mono);font-size:0.72rem;color:${passed ? 'var(--neon-green)' : 'var(--color-error)'};">
          ${escapeHtml(detail)}
        </div>
      </div>
    `;
    DOM.testResultsList.appendChild(card);
  });

  const totalTime = performance.now() - startTime;
  DOM.testTotalTime.textContent = `${totalTime.toFixed(2)} ms`;
  DOM.testPassCount.textContent = `${passCount} / ${SELF_TEST_SUITE.length}`;

  if (passCount === SELF_TEST_SUITE.length) {
    DOM.testOverallStatus.textContent = 'ALL TESTS PASSED';
    DOM.testOverallStatus.className = 'summary-val text-neon';
    showToast(`All ${SELF_TEST_SUITE.length} automated tests passed in ${totalTime.toFixed(2)} ms!`, 'success');
  } else {
    DOM.testOverallStatus.textContent = 'TEST FAILURES DETECTED';
    DOM.testOverallStatus.className = 'summary-val text-error';
    showToast(`${SELF_TEST_SUITE.length - passCount} tests failed.`, 'error');
  }
}

/* ==========================================================================
   10. MATRIX CANVAS BACKGROUND (SUBTLE CYBER GRID / MATRIX RAIN)
   ========================================================================== */

function initMatrixCanvas() {
  const canvas = document.getElementById('matrix-canvas');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = window.innerHeight);

  window.addEventListener('resize', () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  });

  const chars = '0123456789ABCDEFΣΩΨλπΔΘ';
  const fontSize = 14;
  const columns = Math.floor(width / fontSize);
  const drops = Array.from({ length: columns }, () => Math.floor(Math.random() * -50));

  let animationFrameId;

  function draw() {
    ctx.fillStyle = 'rgba(6, 10, 8, 0.08)';
    ctx.fillRect(0, 0, width, height);

    ctx.font = `${fontSize}px monospace`;

    for (let i = 0; i < drops.length; i++) {
      const text = chars[Math.floor(Math.random() * chars.length)];
      // Mostly mint #70FFD2 with occasional luminous cream #FFFC8C character
      ctx.fillStyle = Math.random() > 0.88 ? '#FFFC8C' : '#70FFD2';
      ctx.fillText(text, i * fontSize, drops[i] * fontSize);

      if (drops[i] * fontSize > height && Math.random() > 0.985) {
        drops[i] = 0;
      }
      drops[i]++;
    }
    animationFrameId = requestAnimationFrame(draw);
  }

  // Check user preference for reduced motion
  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  if (!prefersReducedMotion.matches) {
    draw();
  }

  prefersReducedMotion.addEventListener('change', e => {
    if (e.matches) {
      cancelAnimationFrame(animationFrameId);
      ctx.clearRect(0, 0, width, height);
    } else {
      draw();
    }
  });
}

/* ==========================================================================
   11. INITIALIZATION & EVENT DISPATCHER
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
  initDOMElements();
  initMatrixCanvas();
  initFileTools();

  // Navigation Links Smooth Activation
  const navLinks = document.querySelectorAll('.nav-link');
  window.addEventListener('scroll', () => {
    const scrollPos = window.scrollY + 120;
    const sections = ['dashboard', 'workspace', 'comparison', 'file-tools', 'self-tests', 'documentation'];
    for (const secId of sections) {
      const el = document.getElementById(secId);
      if (el) {
        const top = el.offsetTop;
        const h = el.offsetHeight;
        if (scrollPos >= top && scrollPos < top + h) {
          navLinks.forEach(link => {
            link.classList.toggle('active', link.getAttribute('href') === `#${secId}`);
          });
          break;
        }
      }
    }
  });

  // Mobile menu toggle
  DOM.navToggle.addEventListener('click', () => {
    const isOpen = DOM.navMenu.classList.toggle('open');
    DOM.navToggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
  });

  navLinks.forEach(link => {
    link.addEventListener('click', () => {
      DOM.navMenu.classList.remove('open');
      DOM.navToggle.setAttribute('aria-expanded', 'false');
    });
  });

  // Cipher Card Selection
  document.querySelectorAll('.cipher-card').forEach(card => {
    card.addEventListener('click', () => {
      const cipherId = card.getAttribute('data-cipher');
      selectCipher(cipherId);
    });

    card.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        const cipherId = card.getAttribute('data-cipher');
        selectCipher(cipherId);
      }
    });
  });

  // Family Filter Tabs
  document.querySelectorAll('.family-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.family-tab').forEach(t => {
        t.classList.remove('active');
        t.setAttribute('aria-selected', 'false');
      });
      tab.classList.add('active');
      tab.setAttribute('aria-selected', 'true');

      const family = tab.getAttribute('data-family');
      AppState.familyFilter = family;

      document.querySelectorAll('.cipher-card').forEach(card => {
        const cardFamily = card.getAttribute('data-family');
        if (family === 'all' || cardFamily === family) {
          card.style.display = 'flex';
        } else {
          card.style.display = 'none';
        }
      });
    });
  });

  // Mode Switchers
  DOM.modeEncrypt.addEventListener('click', () => setMode('encrypt'));
  DOM.modeDecrypt.addEventListener('click', () => setMode('decrypt'));

  // Workspace Actions
  DOM.executeBtn.addEventListener('click', executeActiveCipher);
  DOM.swapBtn.addEventListener('click', swapInputOutput);
  DOM.clearBtn.addEventListener('click', clearBuffers);
  DOM.copyBtn.addEventListener('click', copyOutputToClipboard);
  DOM.downloadBtn.addEventListener('click', downloadOutput);

  // Text Input Counter
  DOM.textInput.addEventListener('input', updateInputCounters);

  // Quick Sample Text Loader
  const loadSampleAction = (text, cipher, keyConfig) => {
    DOM.textInput.value = text;
    updateInputCounters();
    selectCipher(cipher);
    setMode('encrypt');

    if (cipher === 'caesar' && typeof keyConfig === 'number') {
      const num = document.getElementById('caesar-num');
      const slider = document.getElementById('caesar-slider');
      const badge = document.getElementById('caesar-badge');
      if (num && slider && badge) {
        num.value = keyConfig;
        slider.value = keyConfig;
        badge.textContent = keyConfig;
      }
    }

    // Scroll smoothly to workspace
    document.getElementById('workspace').scrollIntoView({ behavior: 'smooth' });
    showToast(`Loaded sample test vector for ${CIPHER_REGISTRY[cipher].name}.`, 'info');
  };

  DOM.quickDemoBtn.addEventListener('click', () => {
    const cipher = CIPHER_REGISTRY[AppState.currentCipher];
    loadSampleAction(cipher.sampleInput, cipher.id, cipher.defaultKey);
  });

  // Hero Sample Demo button (Requirements Section 13)
  DOM.ctaSampleDemo.addEventListener('click', () => {
    loadSampleAction('NETWORK SECURITY', 'caesar', 5);
    executeActiveCipher();
  });

  // Comparison Module
  DOM.runCompareBtn.addEventListener('click', runAlgorithmComparison);

  // Verification Suite
  DOM.runAllTestsBtn.addEventListener('click', runAllSelfTests);

  // Exit Modal Dialog
  DOM.exitBtn.addEventListener('click', () => {
    DOM.exitModal.classList.remove('hidden');
    DOM.modalResetBtn.focus();
  });

  DOM.modalCloseBtn.addEventListener('click', () => {
    DOM.exitModal.classList.add('hidden');
  });

  DOM.modalCancelBtn.addEventListener('click', () => {
    DOM.exitModal.classList.add('hidden');
  });

  DOM.modalResetBtn.addEventListener('click', () => {
    clearBuffers();
    selectCipher('caesar');
    setMode('encrypt');
    DOM.exitModal.classList.add('hidden');
    showToast('Workspace reset to initial state.', 'info');
  });

  window.addEventListener('keydown', e => {
    if (e.key === 'Escape' && !DOM.exitModal.classList.contains('hidden')) {
      DOM.exitModal.classList.add('hidden');
    }
  });

  DOM.exitModal.addEventListener('click', e => {
    if (e.target === DOM.exitModal) {
      DOM.exitModal.classList.add('hidden');
    }
  });

  // Initialize Default State: Caesar with shift 3
  selectCipher('caesar');
  setMode('encrypt');
  updateInputCounters();

  // Run initial test suite so dashboard shows green pass state right away
  runAllSelfTests();
  runAlgorithmComparison();

  console.log('CRYPT//CORE Classical Cryptography Toolkit Engine Initialized.');
});
