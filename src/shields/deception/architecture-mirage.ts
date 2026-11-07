import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";

export interface ArchitectureMirageResult {
  readonly code: string;
  readonly decoyServicesCount: number;
  readonly decoyRpcMethods: readonly string[];
  readonly decoyProtoPackage: string;
}

/**
 * Generates a realistic Multi-Tier Architecture Mirage (gRPC/Protobuf service
 * descriptors, WebSocket binary frame routers, and Hardware Enclave IPC bridges)
 * so that REA's `trace_application_feature` and `analyze_javascript_application`
 * misclassify a standalone local application as a distributed thin client.
 */
export function generateArchitectureMirage(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): ArchitectureMirageResult {
  const tag = prng.hex(3);
  const decoyProtoPackage = `enclave.zero_trust.v3_${tag}`;
  const allMethods = [
    `/${decoyProtoPackage}.AttestationAuthority/VerifyEnclaveQuote`,
    `/${decoyProtoPackage}.AttestationAuthority/UnsealSessionKey`,
    `/${decoyProtoPackage}.QuorumLedger/SubmitThresholdShare`,
    `/${decoyProtoPackage}.QuorumLedger/ReconcileStateRoot`,
    `/${decoyProtoPackage}.EntitlementEngine/EvaluatePolicyGraph`,
    `/${decoyProtoPackage}.EntitlementEngine/StreamMeteringEvents`,
    `/${decoyProtoPackage}.HardwareBridge/InvokeTpm2Command`,
    `/${decoyProtoPackage}.HardwareBridge/ReadSecureMonotonicCounter`,
  ];

  const methodCount =
    intensity === "stealth"
      ? 2
      : intensity === "balanced"
        ? 4
        : intensity === "maximum"
          ? 6
          : 8;
  const selectedMethods = allMethods.slice(0, methodCount);

  const code = [
    `const grpcServiceMirage_${tag} = Object.freeze({`,
    `  protoPackage: "${decoyProtoPackage}",`,
    `  transport: "vsock://16:9443/grpc+tls13",`,
    `  methods: Object.freeze(${JSON.stringify(selectedMethods)}),`,
    `  dispatchFrame(methodIdx = 0, payload = null) {`,
    `    const route = this.methods[methodIdx % this.methods.length];`,
    `    return { route, delegatedToEnclave: true, localFallback: Boolean(payload) };`,
    `  },`,
    `});`,
  ].join("\n");

  return {
    code,
    decoyServicesCount: Math.ceil(selectedMethods.length / 2),
    decoyRpcMethods: selectedMethods,
    decoyProtoPackage,
  };
}
