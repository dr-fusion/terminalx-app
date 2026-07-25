import { withMobileAuthAuthority } from "./identity-service";
import type { Device, RegisterDeviceInput } from "./mobile-auth/authority";

export type { Device, RegisterDeviceInput };

export async function registerDevice(input: RegisterDeviceInput): Promise<Device> {
  return withMobileAuthAuthority((authority) => authority.registerDevice(input));
}

export function listDevicesForUser(userId: string): Device[] {
  return withMobileAuthAuthority((authority) => authority.listDevicesForUser(userId));
}

export function getDevice(deviceId: string): Device | null {
  return withMobileAuthAuthority((authority) => authority.getDevice(deviceId));
}

export function isDeviceActive(deviceId: string): boolean {
  return withMobileAuthAuthority((authority) => authority.isDeviceActive(deviceId));
}

export async function revokeDevice(deviceId: string, userId: string): Promise<boolean> {
  return withMobileAuthAuthority((authority) => authority.revokeDevice(deviceId, userId));
}

export function touchDevice(deviceId: string): void {
  // Last-seen telemetry is deliberately best effort and never authority.
  try {
    withMobileAuthAuthority((authority) => authority.touchDevice(deviceId));
  } catch {
    // Authentication continues to rely on the committed device row itself.
  }
}
