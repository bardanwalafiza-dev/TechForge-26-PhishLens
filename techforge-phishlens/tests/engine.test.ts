import { verifyUpi } from '../src/lib/upi.ts';
import { analyzeDomain } from '../src/lib/domain.ts';
import { analyzeTarget, anonymizeUrlParameters } from '../src/lib/engine.ts';

console.log('--- Testing NPCI UPI Verification ---');
const validUpi = verifyUpi('merchant@oksbi');
console.log('Valid SBI:', validUpi.verdict, validUpi.bankName);
if (validUpi.verdict !== 'SAFE') throw new Error('Valid UPI failed');

const fakeHandle = verifyUpi('test@nonexistentbankhandle');
console.log('Fake Handle:', fakeHandle.verdict, fakeHandle.reasons[0]);
if (fakeHandle.verdict !== 'DANGEROUS') throw new Error('Fake handle not caught');

const blockedUpi = verifyUpi('lotterywinner@okhdfcbank');
console.log('Blocked UPI:', blockedUpi.verdict, blockedUpi.score);
if (blockedUpi.verdict !== 'DANGEROUS') throw new Error('Blocked UPI not flagged dangerous');

console.log('\n--- Testing Domain & Homoglyph Engine ---');
const realGoogle = analyzeDomain('google.com');
console.log('Real Google:', realGoogle.verdict, realGoogle.score);
if (realGoogle.verdict !== 'SAFE') throw new Error('Real Google failed');

const typosquat = analyzeDomain('secure-hdfc-kyc.com');
console.log('Typosquat:', typosquat.verdict, typosquat.targetBrand?.brand);
if (typosquat.verdict !== 'DANGEROUS') throw new Error('Typosquat not caught');

const homoglyph = analyzeDomain('g\u043E\u043Egle.com');
console.log('Homoglyph attack:', homoglyph.verdict, homoglyph.detectedHomoglyphs.length);
if (homoglyph.detectedHomoglyphs.length === 0) throw new Error('Homoglyph not detected');

console.log('\n--- Testing Zero-Trust False QR Protection ---');
// 1. False QR code must NEVER be SAFE
const falseQr1 = analyzeTarget('https://false-qr.com/pay');
console.log('False QR (false-qr.com):', falseQr1.verdict, 'Score:', falseQr1.riskScore);
if (falseQr1.verdict === 'SAFE') throw new Error('False QR code was incorrectly marked SAFE!');

const falseQr2 = analyzeTarget('https://fake-login-bank.xyz');
console.log('False QR (fake-login-bank.xyz):', falseQr2.verdict, 'Score:', falseQr2.riskScore);
if (falseQr2.verdict !== 'DANGER') throw new Error('Fake login bank was not marked DANGER!');

const unverifiedSite = analyzeTarget('https://random-unknown-domain-123.com');
console.log('Unverified domain:', unverifiedSite.verdict, 'Score:', unverifiedSite.riskScore);
if (unverifiedSite.verdict === 'SAFE') throw new Error('Unverified domain was marked SAFE! Must be CAUTION.');

// 2. Anti-Collect trick
const collectScam = analyzeTarget('upi://pay?pa=scammer@oksbi&am=5000&tn=Receive%20Cashback%20Reward');
console.log('Collect Scam Verdict:', collectScam.verdict, 'Collect Trick:', collectScam.isCollectTrick);
if (!collectScam.isCollectTrick || collectScam.verdict !== 'DANGER') throw new Error('Anti-Collect trick failed to trigger');

// 3. SHA-256 parameter hashing anonymization
const sensitiveUrl = 'https://portal.bank.com/reset?token=secret123&phone=9876543210';
const anonymized = anonymizeUrlParameters(sensitiveUrl);
console.log('Anonymized URL:', anonymized);
if (anonymized.includes('secret123') || anonymized.includes('9876543210')) throw new Error('Sensitive query parameters not anonymized');

// 4. Shortener unroller graph
const shortened = analyzeTarget('https://bit.ly/sbi-urgent-update');
console.log('Shortened Hops:', shortened.redirectChain.length, 'Flagged:', shortened.hasRedirectChain);
if (!shortened.hasRedirectChain) throw new Error('Shortener redirect unroller failed');

// 5. Plain-English 1-Sentence Output check
console.log('Plain English Sentence:', shortened.plainEnglishVerdict);
if (!shortened.plainEnglishVerdict || typeof shortened.plainEnglishVerdict !== 'string') throw new Error('Missing plain-English verdict');

// 6. Existing verified UPI IDs and QR codes must be SAFE
const verifiedUpi = analyzeTarget('upi://pay?pa=store@oksbi&pn=Official%20Store');
console.log('Verified UPI QR (store@oksbi):', verifiedUpi.verdict, 'Score:', verifiedUpi.riskScore);
if (verifiedUpi.verdict !== 'SAFE') throw new Error('Existing verified UPI QR failed to show SAFE!');

const verifiedGPay = analyzeTarget('user@okhdfcbank');
console.log('Verified GPay (user@okhdfcbank):', verifiedGPay.verdict, 'Score:', verifiedGPay.riskScore);
if (verifiedGPay.verdict !== 'SAFE') throw new Error('Verified GPay handle failed to show SAFE!');

// 7. False UPI QR with unauthorized handle must be DANGER
const falseUpiQr = analyzeTarget('upi://pay?pa=scam@unauthorizedbank&pn=Fake');
console.log('False UPI QR with rogue handle:', falseUpiQr.verdict, 'Score:', falseUpiQr.riskScore);
if (falseUpiQr.verdict !== 'DANGER') throw new Error('False UPI QR was not flagged DANGER!');

// 8. Raw unknown QR code text must NEVER be marked SAFE
const rawTextQr = analyzeTarget('QR-CODE-RANDOM-PAYLOAD-99281');
console.log('Raw unknown QR payload:', rawTextQr.verdict, 'Score:', rawTextQr.riskScore);
if (rawTextQr.verdict === 'SAFE') throw new Error('Raw unknown QR payload was incorrectly marked SAFE!');

console.log('\nAll PhishLens security & Zero-Trust tests PASSED successfully!');
