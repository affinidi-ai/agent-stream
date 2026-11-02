import { useCallback, useEffect, useRef, useState } from 'react';
import { apiClient } from '../../../api';
import type { integrationIntegration } from '../../../components/connection-points/IntegrationsStep';
import type { LLMProvider, PipeFormData } from '../types';
import { buildPipePayload } from '../pipeMappingHelpers';
import { showPipeToast } from '../pipeToast';
import { getRandomWord } from '../../../utils/stringUtils';
import { formatApiError } from '../../../utils/apiError';

export interface UsePipeSaveArgs {
  pipeId?: string;
  isNew: boolean;
  llmProviders: LLMProvider[];
  formData: PipeFormData;
  integrations: integrationIntegration[];
  setFormData: React.Dispatch<React.SetStateAction<PipeFormData>>;
  isModified: boolean;
  setIsModified: (value: boolean) => void;
  reloadPipe: () => Promise<void>;
  navigate: (path: string) => void;
  /** Snapshot the live builder canvas (node positions/view) at save time. */
  getCanvasBlob?: () => unknown;
  /**
   * Returns the first reason the surface cannot be saved (an incomplete or
   * invalid canvas node), or null when the canvas is valid. When it returns a
   * `nodeId`, the blocking toast offers a "Show me" jump to that node.
   */
  getBlockingReason?: () => { message: string; nodeId?: string } | null;
  /** Reveal the offending node on the canvas (drives the toast's "Show me"). */
  onShowNode?: (nodeId: string) => void;
  /**
   * Build the full-snapshot variant catalog from the form being saved.
   * Returns the wire `variants[]`, the `default_variant_id`, and the base
   * behavioural snapshot (so the base pipe is written from base, not from
   * the active variant). Returns null when the pipe has no variant manager
   * wired (then the form's own fields are saved with no variants).
   */
  buildVariantsSlice?: (form: PipeFormData) => {
    variants: unknown[];
    defaultVariantId: string | null;
    baseSnapshot: Partial<PipeFormData> & { canvas?: unknown };
  } | null;
}

export interface PipeSave {
  saving: boolean;
  handleSave: () => void;
  handleDelete: () => Promise<void>;
}

/** Minimal shape of a pipe record needed to detect IDE catalogue links. */
interface IdeCatalogLink {
  id: string;
  name?: string;
  status?: string;
  pipe_type?: {
    type?: string;
    config?: { members?: Array<{ pipe_id?: string }> };
  };
}

/**
 * Returns the display names of every IDE surface whose catalogue links to the
 * given LLM surface id, so deletion can warn about the broken dependency
 * before it happens. Deleted IDE surfaces are ignored.
 */
export function ideSurfacesLinkingPipe(pipes: unknown, pipeId: string): string[] {
  const list = Array.isArray(pipes) ? (pipes as IdeCatalogLink[]) : [];
  return list
    .filter(
      p =>
        p?.pipe_type?.type === 'ide_catalog' &&
        p?.status !== 'deleted' &&
        (p?.pipe_type?.config?.members ?? []).some(m => m?.pipe_id === pipeId)
    )
    .map(p => p.name || p.id);
}

/**
 * Save / delete lifecycle for the pipe editor plus the unsaved-changes guards
 * (beforeunload + Ctrl/Cmd+S). The pure payload transform lives in
 * `pipeMapping`; this hook performs the requests and owns toasts/navigation.
 */
export function usePipeSave(args: UsePipeSaveArgs): PipeSave {
  const {
    pipeId,
    isNew,
    llmProviders,
    formData,
    integrations,
    setFormData,
    isModified,
    setIsModified,
    reloadPipe,
    navigate,
    getCanvasBlob,
    getBlockingReason,
    onShowNode,
    buildVariantsSlice,
  } = args;

  const [saving, setSaving] = useState(false);
  const savingRef = useRef(false);

  const performSave = useCallback(
    async (currentFormData: PipeFormData, currentIntegrations: integrationIntegration[]) => {
      setSaving(true);
      try {
        const canvas = getCanvasBlob?.() ?? (currentFormData as { canvas?: unknown }).canvas;
        const formWithCanvas = { ...currentFormData, canvas } as PipeFormData;
        const variantsSlice = buildVariantsSlice?.(formWithCanvas) ?? undefined;
        const updatedPipe = buildPipePayload({
          formData: formWithCanvas,
          integrations: currentIntegrations,
          llmProviders,
          isNew,
          pipeId,
          variantsSlice,
        });

        const response = await apiClient.fetch(
          isNew ? '/api/v1/pipes' : `/api/v1/pipes/${pipeId}`,
          {
            method: isNew ? 'POST' : 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(updatedPipe),
          }
        );

        if (!response.ok) {
          const errorText = await response.text();
          throw new Error(formatApiError(response.status, errorText, response.statusText));
        }

        setIsModified(false);
        showPipeToast('success', `Surface "${currentFormData.name}" has been successfully saved.`);

        if (isNew) {
          navigate(`/pipes/${updatedPipe.id}`);
        } else {
          await reloadPipe();
        }
      } catch (error) {
        console.error('Failed to update surface:', error);
        showPipeToast(
          'error',
          `Failed to update surface: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
      } finally {
        savingRef.current = false;
        setSaving(false);
      }
    },
    [
      llmProviders,
      isNew,
      pipeId,
      navigate,
      reloadPipe,
      setIsModified,
      getCanvasBlob,
      buildVariantsSlice,
    ]
  );

  const handleSave = useCallback(() => {
    if (savingRef.current) return;
    const blocking = getBlockingReason?.();
    if (blocking) {
      showPipeToast(
        'error',
        blocking.message,
        blocking.nodeId
          ? { label: 'Show me', onClick: () => onShowNode?.(blocking.nodeId!) }
          : undefined
      );
      return;
    }
    // An LLM Surface is always saved with a name. If one is somehow
    // missing (e.g. it was cleared), auto-generate a memorable default
    // and save with it rather than blocking the user.
    const named =
      formData.name && formData.name.trim()
        ? formData
        : { ...formData, name: `surface-${getRandomWord()}-${getRandomWord()}` };
    // Enable-first list controls: if the user emptied the list while the
    // switch was on, force the switch off on save so the UI matches what
    // the server will persist.
    const normalized: PipeFormData = {
      ...named,
      routing_enabled: named.routing_enabled && (named.routing_rules?.length ?? 0) > 0,
      usage_alerts_enabled: named.usage_alerts_enabled && (named.usage_alerts?.length ?? 0) > 0,
    };
    savingRef.current = true;
    setFormData(normalized);
    void performSave(normalized, integrations);
  }, [formData, integrations, performSave, setFormData, getBlockingReason, onShowNode]);

  const handleDelete = useCallback(async () => {
    setSaving(true);
    try {
      // Warn if any IDE surface's catalogue links to this LLM surface, so the
      // broken cross-surface dependency is surfaced before the delete happens.
      try {
        const listResponse = await apiClient.fetch('/api/v1/pipes');
        if (listResponse.ok) {
          const linkedBy = ideSurfacesLinkingPipe(await listResponse.json(), pipeId ?? '');
          if (linkedBy.length > 0) {
            const names = linkedBy.map(n => `\u2022 ${n}`).join('\n');
            const proceed = window.confirm(
              `This LLM surface is linked by ${linkedBy.length} IDE surface${
                linkedBy.length === 1 ? '' : 's'
              }:\n\n${names}\n\nDeleting it will break those IDE catalogue entries. Delete anyway?`
            );
            if (!proceed) {
              setSaving(false);
              return;
            }
          }
        }
      } catch (checkError) {
        console.error('Failed to check IDE surface references:', checkError);
      }

      const response = await apiClient.fetch(`/api/v1/pipes/${pipeId}`, {
        method: 'DELETE',
      });
      if (!response.ok) {
        const errorText = await response.text().catch(() => '');
        throw new Error(formatApiError(response.status, errorText, response.statusText));
      }
      showPipeToast('success', `Pipe "${formData.name}" has been successfully deleted.`);
      navigate('/pipes');
    } catch (error) {
      console.error('Failed to delete pipe:', error);
      showPipeToast(
        'error',
        `Failed to delete pipe: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    } finally {
      setSaving(false);
    }
  }, [pipeId, formData.name, navigate]);

  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (isModified) {
        e.preventDefault();
      }
    };
    window.addEventListener('beforeunload', handleBeforeUnload);
    return () => window.removeEventListener('beforeunload', handleBeforeUnload);
  }, [isModified]);

  useEffect(() => {
    const handleKeyboardSave = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 's') {
        event.preventDefault();
        if ((isNew || isModified) && !saving) {
          handleSave();
        }
      }
    };
    document.addEventListener('keydown', handleKeyboardSave);
    return () => {
      document.removeEventListener('keydown', handleKeyboardSave);
    };
  }, [isNew, isModified, saving, handleSave]);

  return { saving, handleSave, handleDelete };
}
