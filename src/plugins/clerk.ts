import { VolidatorClient, LogPayload } from "../index";
import { withVolidator } from "../middleware/next";

export interface ClerkAuditConfig {
  /** The Volidator instance */
  client: VolidatorClient;
  /** Pass Clerk's auth() function from @clerk/nextjs/server */
  getAuth: () => any;
}

/**
 * Creates a Clerk-specific Next.js middleware wrapper.
 * Automatically injects the Clerk userId as the actor, and extracts IP/User-Agent.
 */
export function createClerkAudit({
  client,
  getAuth,
}: ClerkAuditConfig): <T extends (req: Request, ctx: any) => any>(
  handler: T
) => (req: Request, ctx?: any, ...args: any[]) => Promise<any> {
  return function withClerkAudit<T extends (req: Request, ctx: any) => any>(
    handler: T
  ): (req: Request, ctx?: any, ...args: any[]) => Promise<any> {
    // Wrap with the base Next.js middleware first
    const baseHandler = withVolidator(client, async (req: Request, ctx: any) => {
      let session: any = null;
      let userId: string | undefined;

      try {
        // Safely extract the Clerk session
        session = getAuth();
        userId = session?.userId;
      } catch (e) {
        console.warn("[Volidator] Failed to execute getAuth() in Clerk plugin", e);
      }

      const originalLog = ctx.volidator.log;
      
      // Override the scoped logger to automatically attach the Clerk actor ID
      ctx.volidator.log = async (payload: LogPayload) => {
        const enrichedPayload = { ...payload };
        
        if (!enrichedPayload.actor && userId) {
          enrichedPayload.actor = userId;
        }

        return originalLog(enrichedPayload);
      };

      // Pass the strongly-typed session down so developers can use it in their handler
      ctx.session = session;
      return handler(req, ctx);
    });

    return baseHandler;
  };
}
