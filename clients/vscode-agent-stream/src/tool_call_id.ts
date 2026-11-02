import { randomUUID } from 'node:crypto';

export function resolveToolCallId(providerId: string | undefined): string {
  return providerId || `call_${randomUUID()}`;
}
