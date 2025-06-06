// Original file: proto/appguard.proto

import type { AppGuardTcpInfo as _appguard_AppGuardTcpInfo, AppGuardTcpInfo__Output as _appguard_AppGuardTcpInfo__Output } from '../appguard/AppGuardTcpInfo';

export interface AppGuardSmtpRequest {
  'token'?: (string);
  'headers'?: ({[key: string]: string});
  'body'?: (string);
  'tcpInfo'?: (_appguard_AppGuardTcpInfo | null);
  '_body'?: "body";
}

export interface AppGuardSmtpRequest__Output {
  'token'?: (string);
  'headers'?: ({[key: string]: string});
  'body'?: (string);
  'tcpInfo'?: (_appguard_AppGuardTcpInfo__Output);
}
