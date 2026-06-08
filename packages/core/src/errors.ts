export class RiskRadarError extends Error {
  constructor(
    public code: string,
    message: string,
    public details: Record<string, unknown> = {},
    public status = 400
  ) {
    super(message);
  }
}

export function apiError(error: unknown) {
  if (error instanceof RiskRadarError) {
    return {
      error: {
        code: error.code,
        message: error.message,
        details: error.details
      }
    };
  }
  return {
    error: {
      code: "internal_error",
      message: error instanceof Error ? error.message : "Unexpected error",
      details: {}
    }
  };
}
