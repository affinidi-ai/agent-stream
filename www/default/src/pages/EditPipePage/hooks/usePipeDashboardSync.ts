import { useEffect } from 'react';
import { WS_NONE, WS_DASHBOARD } from '../../../utils/wsSubscriptions';

/**
 * Background data wiring for the pipe editor: set dashboard filters for the
 * open pipe, subscribe to the dashboard WS feed, switch to the filtered view,
 * and trigger a stats load once the filter is in place. Extracted verbatim
 * from EditPipePage; `state`/`actions` come from the app context.
 */
export function usePipeDashboardSync(
  pipeId: string | undefined,
  activeTab: string,
  state: any,
  actions: any
): void {
  useEffect(() => {
    if (!pipeId || pipeId === 'new') {
      actions.setDashboardFilters(null);
      return;
    }
    if (state.dashboardFilters?.pipe_id !== pipeId) {
      actions.setDashboardFilters({ pipe_id: pipeId });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pipeId]);

  useEffect(() => {
    actions.setWsSubscription(WS_DASHBOARD);
    return () => {
      actions.setWsSubscription(WS_NONE);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!pipeId || pipeId === 'new') {
      return;
    }
    actions.setActiveView('filtered');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, pipeId]);

  useEffect(() => {
    const activeStore = state.activeView === 'global' ? state.globalState : state.filteredState;
    const shouldLoad =
      state.dashboardFilters?.pipe_id === pipeId &&
      activeStore.lastSyncTimestamp === null &&
      pipeId &&
      pipeId !== 'new';

    if (shouldLoad) {
      actions.loadDashboardStats(true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    state.dashboardFilters,
    state.activeView,
    state.globalState.lastSyncTimestamp,
    state.filteredState.lastSyncTimestamp,
    pipeId,
  ]);
}
