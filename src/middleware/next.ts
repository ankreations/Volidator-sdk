import { VolidatorClient, LogPayload } from "../index";

/**
 * Next.js App Router Middleware for Volidator.
 * Automatically extracts telemetry context (IP, User Agent, Location)
 * from the Next.js standard Request object and injects it into every
 * `volidator.log()` and `volidator.compliance.*()` call made inside
 * the wrapped handler.
 */
export function withVolidator<T extends Function>(
  client: VolidatorClient,
  handler: T
): (req: Request, ctx?: any, ...args: any[]) => Promise<any> {
  return async (req: Request, ctx: any = {}, ...args: any[]) => {
    const extractedContext = VolidatorClient.extractContext(req);

    // ---------------------------------------------------------------------------
    // Scoped log — merges request-level IP/UA context into every log call.
    // ---------------------------------------------------------------------------
    const scopedLog = async (payload: LogPayload) => {
      return client.log({
        ...payload,
        context: {
          ...extractedContext,
          ...payload.context,
          location: {
            ...extractedContext.location,
            ...(payload.context?.location || {}),
          },
          device: {
            ...extractedContext.device,
            ...(payload.context?.device || {}),
          },
        },
      });
    };

    // ---------------------------------------------------------------------------
    // Scoped compliance — mirrors VolidatorCompliance but routes through
    // scopedLog so that IP/UA telemetry is preserved in compliance events.
    //
    // Previously this passed client.compliance directly, which called
    // client.log() without the request context — silently dropping telemetry
    // from every compliance audit event.
    // ---------------------------------------------------------------------------
    const withControl = (
      action: string,
      soc2Control: string,
      isoControl: string,
      payload: Omit<LogPayload, "action">
    ) =>
      scopedLog({
        ...payload,
        action,
        metadata: {
          ...payload.metadata,
          soc2_control: soc2Control,
          iso27001: isoControl,
        },
      });

    const scopedCompliance = {
      accessRevoked: (p: Omit<LogPayload, "action">) =>
        withControl("access.revoked", "CC6.1", "A.9.2.6", p),
      accessGranted: (p: Omit<LogPayload, "action">) =>
        withControl("access.granted", "CC6.1", "A.9.2.1", p),
      dataExported: (p: Omit<LogPayload, "action">) =>
        withControl("data.exported", "CC6.6", "A.12.4.1", p),
      systemConfigChanged: (p: Omit<LogPayload, "action">) =>
        withControl("system.config_changed", "CC6.2", "A.12.1.2", p),
      mfaEnabled: (p: Omit<LogPayload, "action">) =>
        withControl("mfa.enabled", "CC6.3", "A.9.4.2", p),
    };

    const newCtx = {
      ...ctx,
      volidator: {
        log: scopedLog,
        compliance: scopedCompliance,
      },
    };

    return handler(req, newCtx, ...args);
  };
}
