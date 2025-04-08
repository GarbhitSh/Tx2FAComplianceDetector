import {
    TransactionEvent,
    Finding,
    FindingSeverity,
    FindingType,
    HandleTransaction,
    getEthersProvider,
  } from "forta-agent";
  import { ethers } from "ethers";
  
  // Define method selectors to monitor
  const highRiskMethods: { [key: string]: string } = {
    transfer: "0xa9059cbb", // transfer(address,uint256)
    approve: "0x095ea7b3", // approve(address,uint256)
    upgradeTo: "0x3659cfe6", // upgradeTo(address)
    delegateCall: "0x5c19a95c", // hypothetical delegateCall()
  };
  
  // 2FA Metadata Keys to Search For
  const expected2FAKeys = ["otp", "nonce", "signedTime", "sessionId"];
  
  // Simple function to check for missing 2FA
  const is2FAMetadataMissing = (data: string): boolean => {
    const lowercase = data.toLowerCase();
    return !expected2FAKeys.some((key) => lowercase.includes(key.toLowerCase()));
  };
  
  const handleTransaction: HandleTransaction = async (
    txEvent: TransactionEvent
  ): Promise<Finding[]> => {
    const findings: Finding[] = [];
  
    const txData = txEvent.transaction.data.toLowerCase();
    const methodSelector = txData.slice(0, 10);
  
    // Check if the function is high-risk
    const isMonitored = Object.values(highRiskMethods).includes(methodSelector);
    if (!isMonitored) return findings;
  
    // Check if 2FA metadata exists
    const missing2FA = is2FAMetadataMissing(txData);
  
    if (missing2FA) {
      const functionName = Object.keys(highRiskMethods).find(
        (name) => highRiskMethods[name] === methodSelector
      );
  
      findings.push(
        Finding.fromObject({
          name: "Missing 2FA for High-Risk Transaction",
          description: `High-risk function "${functionName}" executed without 2FA metadata.`,
          alertId: "VENN-2FA-1",
          type: FindingType.Suspicious,
          severity: FindingSeverity.High,
          protocol: "ethereum",
          metadata: {
            from: txEvent.transaction.from,
            to: txEvent.transaction.to ?? "",
            function: functionName ?? "unknown",
            input: txData.slice(0, 100) + "...",
          },
        })
      );
    }
  
    return findings;
  };
  
  export default {
    handleTransaction,
  };
  