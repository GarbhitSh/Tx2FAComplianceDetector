import { createTransactionEvent } from "forta-agent";
import { ethers } from "ethers";
import Tx2FAComplianceDetector from "./Tx2FAComplianceDetector";

const mockTx = ({
  from,
  to,
  data,
}: {
  from?: string;
  to?: string;
  data: string;
}) =>
  createTransactionEvent({
    transaction: {
      hash: "0x123",
      from: from || "0xUserWallet",
      to: to || "0xHighRiskContract",
      value: "0",
      data,
    },
    addresses: {},
    block: {},
    logs: [],
  });

describe("Tx2FAComplianceDetector", () => {
  it("should trigger alert for high-risk tx with missing 2FA metadata", async () => {
    const txData =
      "0xa9059cbb000000000000000000000000abc0000000000000000000000000000000000000000000000000000000000002710"; // transfer()

    const findings = await Tx2FAComplianceDetector.handleTransaction(
      mockTx({ data: txData })
    );

    expect(findings.length).toBe(1);
    expect(findings[0].name).toBe("Missing 2FA for High-Risk Transaction");
  });

  it("should not trigger if 2FA metadata is present", async () => {
    const txData =
      "0xa9059cbb000000000000000000000000abc0000000000000000000000000000000000000000000000000000000000002710ffotpffsignedTime";

    const findings = await Tx2FAComplianceDetector.handleTransaction(
      mockTx({ data: txData })
    );

    expect(findings.length).toBe(0);
  });

  it("should ignore non-monitored function calls", async () => {
    const txData = "0x12345678deadbeef";

    const findings = await Tx2FAComplianceDetector.handleTransaction(
      mockTx({ data: txData })
    );

    expect(findings.length).toBe(0);
  });

  it("should handle approve() with missing 2FA metadata", async () => {
    const txData =
      "0x095ea7b3000000000000000000000000def0000000000000000000000000000000000000000000000000000000000002710";

    const findings = await Tx2FAComplianceDetector.handleTransaction(
      mockTx({ data: txData })
    );

    expect(findings.length).toBe(1);
    expect(findings[0].alertId).toBe("VENN-2FA-1");
  });
});
