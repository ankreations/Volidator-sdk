import { VolidatorClient, LogPayload } from "../index";

/**
 * Next.js App Router Middleware for Volidator.
 * Automatically extracts telemetry context (IP, User Agent, Location) 
 * from the Next.js standard Request object.
 */
export function withVolidator<T extends Function>(client: VolidatorClient, handler: T) {
  return async (req: Request, ctx: any = {}, ...args: any[]) => {
    const extractedContext = VolidatorClient.extractContext(req);

    // Create a request-scoped volidator instance
    const scopedVolidator = {
      log: async (payload: LogPayload) => {
        return client.log({
          ...payload,
          context: {
            ...extractedContext,
            ...payload.context,
            location: {
              ...extractedContext.location,
              ...(payload.context?.location || {})
            },
            device: {
              ...extractedContext.device,
              ...(payload.context?.device || {})
            }
          }
        });
      },
      compliance: client.compliance, // Note: compliance functions don't use the scoped wrapper directly unless implemented
    };

    // Inject into Next.js context object
    const newCtx = {
      ...ctx,
      volidator: scopedVolidator
    };

    return handler(req, newCtx, ...args);
  };
}
