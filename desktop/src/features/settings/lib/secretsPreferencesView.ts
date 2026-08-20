export interface MutableBwsConfiguration {
  accessToken?: string;
  projectId: string;
  bindings?: Array<{ logicalKey: string; secretId: string }>;
}

export async function configureBwsThenTest<TStatus, TTestResult>(
  request: MutableBwsConfiguration,
  configure: (request: MutableBwsConfiguration) => Promise<TStatus>,
  testConnectivity: () => Promise<TTestResult>,
): Promise<{ status: TStatus; testResult: TTestResult }> {
  try {
    const status = await configure(request);
    delete request.accessToken;
    const testResult = await testConnectivity();
    return { status, testResult };
  } finally {
    delete request.accessToken;
  }
}

export function leaseSecondsRemaining(
  expiresAt: string,
  nowMs: number,
): number {
  const expiresAtMs = Date.parse(expiresAt);
  if (!Number.isFinite(expiresAtMs)) return 0;
  return Math.max(0, Math.ceil((expiresAtMs - nowMs) / 1_000));
}

export function formatLeaseCountdown(seconds: number): string {
  if (seconds <= 0) return "expired";
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return minutes > 0 ? `${minutes}m ${remainder}s` : `${remainder}s`;
}
