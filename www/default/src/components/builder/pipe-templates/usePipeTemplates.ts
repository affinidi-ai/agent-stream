/**
 * `usePipeTemplates` — lazy fetch + cache of the pipe templates list,
 * plus CRUD helpers. Mirrors `useSurfaceTemplates` so the panel UX is
 * consistent across the two builders.
 */

import { useCallback, useEffect, useState } from 'react';
import { apiClient, type PipeTemplate } from '../../../api';

export interface UsePipeTemplatesResult {
  templates: PipeTemplate[];
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  create: (tpl: Partial<PipeTemplate>) => Promise<PipeTemplate>;
  update: (id: string, tpl: Partial<PipeTemplate>) => Promise<PipeTemplate>;
  remove: (id: string) => Promise<void>;
  importTemplate: (payload: unknown) => Promise<PipeTemplate>;
  exportTemplate: (id: string) => Promise<string>;
}

export function usePipeTemplates(): UsePipeTemplatesResult {
  const [templates, setTemplates] = useState<PipeTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await apiClient.listPipeTemplates();
      setTemplates(list);
    } catch (e: any) {
      setError(e?.message ?? 'Failed to load templates');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const create = useCallback(
    async (tpl: Partial<PipeTemplate>) => {
      const created = await apiClient.createPipeTemplate(tpl);
      await refresh();
      return created;
    },
    [refresh]
  );

  const update = useCallback(
    async (id: string, tpl: Partial<PipeTemplate>) => {
      const updated = await apiClient.updatePipeTemplate(id, tpl);
      await refresh();
      return updated;
    },
    [refresh]
  );

  const remove = useCallback(
    async (id: string) => {
      await apiClient.deletePipeTemplate(id);
      await refresh();
    },
    [refresh]
  );

  const importTemplate = useCallback(
    async (payload: unknown) => {
      const imported = await apiClient.importPipeTemplate(payload);
      await refresh();
      return imported;
    },
    [refresh]
  );

  const exportTemplate = useCallback(async (id: string) => {
    return apiClient.exportPipeTemplate(id);
  }, []);

  return {
    templates,
    loading,
    error,
    refresh,
    create,
    update,
    remove,
    importTemplate,
    exportTemplate,
  };
}

/**
 * Sort pipe templates for display: lower `sort_priority` first, ties
 * broken alphabetically by name. Templates without a priority sort last.
 */
export function sortPipeTemplatesForDisplay(templates: PipeTemplate[]): PipeTemplate[] {
  const priority = (t: PipeTemplate) =>
    t.sort_priority === undefined || t.sort_priority === null
      ? Number.MAX_SAFE_INTEGER
      : t.sort_priority;
  return [...templates].sort((a, b) => {
    const pa = priority(a);
    const pb = priority(b);
    if (pa !== pb) return pa - pb;
    return a.name.localeCompare(b.name);
  });
}
