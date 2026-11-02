import { useEffect, useState } from 'react';
import { fetchSeries, monthToDateWindow, sumWindow, type WindowTotals } from './usageSeries';

/** Fetch the month-to-date spend/token totals for a single telemetry series key
 * (e.g. `member:{id}` or `team:{id}`). Returns `null` until loaded, or when no
 * key is supplied (e.g. an unsaved entity). */
export function useCapUsage(seriesKey: string | null): WindowTotals | null {
  const [totals, setTotals] = useState<WindowTotals | null>(null);

  useEffect(() => {
    if (!seriesKey) {
      setTotals(null);
      return;
    }
    const controller = new AbortController();
    fetchSeries([seriesKey], monthToDateWindow(), 400, 'auto', controller.signal)
      .then(series => setTotals(sumWindow(series[0])))
      .catch(() => {
        /* leave totals null on error; the bar simply shows nothing */
      });
    return () => controller.abort();
  }, [seriesKey]);

  return totals;
}
