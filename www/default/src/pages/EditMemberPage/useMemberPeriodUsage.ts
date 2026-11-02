import { useEffect, useState } from 'react';
import { apiClient } from '../../api';
import type { MemberPeriodUsage } from './memberHelpers';

/** Fetch a saved member's usage for its current budget period. `null` until
 * loaded, for an unsaved member, or on error. */
export function useMemberPeriodUsage(memberId: string): MemberPeriodUsage | null {
  const [usage, setUsage] = useState<MemberPeriodUsage | null>(null);

  useEffect(() => {
    if (!memberId) {
      setUsage(null);
      return;
    }
    let cancelled = false;
    apiClient
      .get<MemberPeriodUsage>(`/members/${encodeURIComponent(memberId)}/usage`)
      .then(response => {
        if (!cancelled) setUsage(response.data);
      })
      .catch(() => {
        if (!cancelled) setUsage(null);
      });
    return () => {
      cancelled = true;
    };
  }, [memberId]);

  return usage;
}
