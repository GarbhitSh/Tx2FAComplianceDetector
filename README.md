# Tx2FAComplianceDetector 🔐
A custom Venn detector to enforce 2-Factor Authentication (2FA) compliance on high-risk Ethereum transactions.

## Overview
Tx2FAComplianceDetector scans Ethereum transactions to identify high-risk operations (e.g., transfer, approve, upgradeTo) that lack 2FA metadata, such as:

* otp (One-Time Password)
* nonce (Replay prevention)
* signedTime (Signed timestamp)
* sessionId (User/session tracking)

## Alert Triggering
If such transactions are detected without this data, the detector triggers an alert to protect user assets from unauthorized access or wallet compromise.

## Purpose
This detector helps teams enforce secure transaction flows, especially for wallets and apps that integrate 2FA at the app or protocol level (e.g., using Gnosis Safe modules or off-chain authenticators). It reduces the risk of:

* Phishing-signed approvals
* Drained wallets via proxy upgrades
* Multisig bypasses through delegate calls

## Functionality
✅ What It Detects
* transfer() or transferFrom() with large value and no 2FA
* approve() of unlimited allowances without OTP validation
* Proxy upgrade calls (upgradeTo, delegateCall) with no 2FA metadata
* Malformed or missing signed metadata in calldata

## How It Works
* Filters transactions for known high-risk function selectors
* Decodes tx.data to check for presence of 2FA-related keywords
* Flags any transaction that lacks proper metadata
* Emits an alert via Venn/Forta APIs
![Alt text](https://github.com/GarbhitSh/Tx2FAComplianceDetector/blob/main/autoD.png)
## File Structure
* /src/detectors/Tx2FAComplianceDetector.ts
* /tests/Tx2FAComplianceDetector.test.ts

## Example Triggers
### Triggered Example
* Function: transfer(address,uint256)
* From: 0xuser123...
* To: 0xtokenABC...
* Calldata: Missing 2FA metadata (otp, nonce) → Finding triggered

### Not Triggered Example
* Function: approve(address,uint256)
* From: 0xuser123...
* To: 0xtokenABC...
* Calldata includes: "otp=123456", "signedTime=..." → Finding NOT triggered

## Trigger Details
* Field: Missing 2FA for High-Risk Transaction
* Alert ID: VENN-2FA-1
* Severity: High
* Type: Suspicious
* Metadata: from, to, function, partial input data
