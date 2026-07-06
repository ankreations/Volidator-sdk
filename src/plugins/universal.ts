import { VolidatorClient, LogPayload } from "../index";
import { withVolidator } from "../middleware/next";

export interface UniversalAuditConfig {
  /** The Volidator instance */
  client: VolidatorClient;
  /** 
   * A callback to extract the actor's user ID from the request or your auth provider.
   * Works universally with Auth0, BetterAuth, NextAuth, Kinde, Supabase, etc.
   */
  getUserId: (req: Request, ctx: any) => Promise<string | undefined> | string | undefined;
  /** Optional callback to extract the full session object */
  getSession?: (req: Request, ctx: any) => Promise<any> | any;
  /** Optional callback to seamlessly inject avatar_url, email, or other properties into encrypted metadata */
  getMetadata?: (req: Request, session: any) => Promise<Record<string, any>> | Record<string, any>;
}

/**
 * Creates a universal Next.js IAM middleware wrapper.
 * Compatible with any authentication provider (Auth0, BetterAuth, Kinde, Supabase, etc).
 */
export function createUniversalAudit({
  client,
  getUserId,
  getSession,
  getMetadata,
}: UniversalAuditConfig): <T extends (req: Request, ctx: any) => any>(
  handler: T
) => (req: Request, ctx?: any, ...args: any[]) => Promise<any> {
  return function withAuthAudit<T extends (req: Request, ctx: any) => any>(
    handler: T
  ): (req: Request, ctx?: any, ...args: any[]) => Promise<any> {
    // Wrap with the base Next.js middleware first (extracts IP & User Agent)
    const baseHandler = withVolidator(client, async (req: Request, ctx: any) => {
      let session: any = null;
      let userId: string | undefined;
      let injectedMetadata: Record<string, any> = {};

      try {
        // Safely extract from any provider using the user's callback
        if (getSession) {
          session = await getSession(req, ctx);
        }

        // Ensure getUserId and getMetadata are called with the resolved session
        userId = await getUserId(req, session ?? ctx);

        if (getMetadata) {
          injectedMetadata = (await getMetadata(req, session ?? ctx)) || {};
        }
      } catch (e) {
        console.warn("[Volidator] Failed to execute IAM callbacks in Universal plugin", e);
      }

      const originalLog = ctx.volidator.log;

      // Override the scoped logger to automatically attach the universal actor ID
      ctx.volidator.log = async (payload: LogPayload) => {
        const enrichedPayload = { ...payload };

        if (!enrichedPayload.actor && userId) {
          enrichedPayload.actor = userId;
        }

        if (Object.keys(injectedMetadata).length > 0) {
          enrichedPayload.metadata = {
            ...injectedMetadata,
            ...(enrichedPayload.metadata || {})
          };
        }

        return originalLog(enrichedPayload);
      };

      // Pass the strongly-typed session down
      ctx.session = session;
      return handler(req, ctx);
    });

    return baseHandler;
  };
}
