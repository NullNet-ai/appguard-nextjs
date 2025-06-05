import {NextRequest, NextResponse} from 'next/server'
import { AppGuardService } from './app-guard-nextjs';
// import { AppGuardTcpInfo } from './proto/appguard/AppGuardTcpInfo';
import { FirewallPolicy } from './proto/appguard/FirewallPolicy';
import {AppGuardResponse__Output} from "./proto/appguard/AppGuardResponse";
import {AppGuardTcpResponse__Output} from "./proto/appguard/AppGuardTcpResponse";
import {AppGuardTcpConnection} from "./proto/appguard/AppGuardTcpConnection";
import {AuthHandler} from "./auth";

type NextjsMiddleware = (req: NextRequest) => Promise<NextResponse>;

export type AppGuardConfig = {
  host: string;
  port: number;
  tls: boolean;
  timeout?: number;
  defaultPolicy: FirewallPolicy;
  firewall: string;
};


export const createAppGuardMiddleware = (config: AppGuardConfig) => {
  console.log("createAppGuardMiddleware");
  const appGuardService = new AppGuardService(config.host, config.port, config.tls);
  let authHandler = new AuthHandler(appGuardService);

  async function initialize() {
    await appGuardService.onModuleInit();
    await authHandler.init();
    await appGuardService.updateFirewall({
        token: authHandler.token(),
        firewall: config.firewall
    })
  }
  initialize();

    const firewallPromise = (promise: Promise<AppGuardResponse__Output>): Promise<AppGuardResponse__Output> => {
        if (config.timeout !== undefined) {
            let timeoutPromise: Promise<AppGuardResponse__Output> = new Promise((resolve, _reject) => {
                setTimeout(resolve, config.timeout, {
                    policy: config.defaultPolicy
                })
            });
            return Promise.race([promise, timeoutPromise])
        } else {
            return promise
        }
    }

    const connectionPromise = (connection: AppGuardTcpConnection): Promise<AppGuardTcpResponse__Output> => {
        let promise = appGuardService.handleTcpConnection(connection);
        if (config.timeout !== undefined) {
            let timeoutPromise: Promise<AppGuardTcpResponse__Output> = new Promise((resolve, _reject) => {
                setTimeout(resolve, config.timeout, {
                    tcpInfo: {
                        connection: connection,
                    }
                })
            });
            return Promise.race([promise, timeoutPromise])
        } else {
            return promise
        }
    }

  // const attachResponseHandlers = (
  //   res: Response,
  //   tcp_info: AppGuardTcpInfo
  // ) => {
  //   // Storing the original send function
  //   // @ts-ignore
  //   const originalSend = res.send;
  //   // @ts-ignore
  //   // const originalJson = res.json;
  //
  //   // Override function
  //   // @ts-ignore
  //   res.send = async function(body: string | Record<string, unknown>) {
  //     // @ts-ignore
  //     const response_headers = res.getHeaders();
  //
  //     // @ts-ignore
  //     const handleHTTPResponseResponse = await firewallPromise(appGuardService.handleHttpResponse(
  //         {
  //             // @ts-ignore
  //             code: res.statusCode,
  //             // @ts-ignore
  //             headers: response_headers as Record<string, string>,
  //             tcpInfo: tcp_info,
  //             // @ts-ignore
  //             token: authHandler.token()
  //         }
  //     ));
  //
  //     if (handleHTTPResponseResponse.policy === FirewallPolicy.DENY) {
  //       // Destroying the socket connection instead of sending the response
  //       // @ts-ignore
  //       res.socket?.destroy();
  //     } else {
  //       // Intercepting the response.send() call
  //       // Calling the original send function
  //       //@ts-expect-error: This function is this context
  //       originalSend.call(this, body);
  //     }
  //   } as Send;
  // };

  const handleIncomingRequest: NextjsMiddleware = async (req): Promise<NextResponse> => {
    console.log("handleIncomingRequest");
    try {
        const sourceIp =
            req.headers.get('x-real-ip') ||
            req.headers.get('x-forwarded-for') || undefined;

        const sourcePort = req.headers.get('x-forwarded-port') ?
            parseInt(req.headers.get('x-forwarded-port') as string, 10) :
            undefined;

      const handleTCPConnectionResponse = await connectionPromise(
          {
              sourceIp: sourceIp,
              sourcePort: sourcePort,
              destinationIp: undefined,
              destinationPort: undefined,
              protocol: req.headers.get('x-forwarded-proto') || undefined,
              token: authHandler.token()
          }
      );
      const handleHTTPRequestResponse = await firewallPromise(appGuardService.handleHttpRequest(
        {
          originalUrl: req.nextUrl.pathname,
          // @ts-ignore
          // headers: req.headers as Record<string, string>,
          method: req.method,
          // @ts-ignore
          // body: req.body,
          // @ts-ignore
          // query: req.nextUrl.searchParams as Record<string, string>,
          tcpInfo: handleTCPConnectionResponse.tcpInfo,
          token: authHandler.token()
        }
      ));

      // console.log(
      //   `Appguard Request Decision- ${FirewallPolicy.ALLOW ? 'Allow' : 'Deny'} `
      // );

      const policy = handleHTTPRequestResponse.policy;
      if (policy === FirewallPolicy.DENY) {
          return NextResponse.json(
              { success: false, message: 'Unauthorized' },
              { status: 401 }
          );
      } else {
        // only attach response handlers if the request is allowed.
        // attach response handlers after we get the req.id
        // attachResponseHandlers(
        //   res,
        //   handleTCPConnectionResponse.tcpInfo as AppGuardTcpInfo
        // );
        return NextResponse.next();
      }
    } catch (error) {
      console.error(error);
      return NextResponse.json(
            { success: false, message: 'Internal server error' },
            { status: 500 }
        );
    }
  };

  return handleIncomingRequest;
};
