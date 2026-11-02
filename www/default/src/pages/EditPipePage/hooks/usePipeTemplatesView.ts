import { useCallback, useEffect, useMemo, useState } from 'react';
import type { PipeTemplate } from '../../../api';
import {
  usePipeTemplates,
  sortPipeTemplatesForDisplay,
  type UsePipeTemplatesResult,
} from '../../../components/builder/pipe-templates/usePipeTemplates';
import { resolvePipeTemplateBlob } from '../../../components/builder/pipe-templates/pipeTemplateBlob';
import { applyPipeTemplateItems } from '../../../components/builder/pipe-templates/pipeItemPlacement';
import type { PipeFormData } from '../types';
import { showPipeToast } from '../pipeToast';

const VALID_VIEWS = ['visual', 'templates', 'monitoring', 'integrations', 'sandbox'];

export interface UsePipeTemplatesViewArgs {
  isNew: boolean;
  initialTab: string | null;
  setSearchParams: (next: { tab: string }, opts: { replace: boolean }) => void;
  setFormData: React.Dispatch<React.SetStateAction<PipeFormData>>;
  setIsModified: (value: boolean) => void;
}

export interface PipeTemplatesView {
  activeTab: string;
  setActiveTab: (key: string) => void;
  handleTabChange: (key: string | null) => void;
  pipePickerShown: boolean;
  setPipePickerShown: (value: boolean) => void;
  applyingStarterId: string | null;
  pickerExpandedId: string | null;
  toggleExpanded: (id: string) => void;
  templatesCreateMode: boolean;
  setTemplatesCreateMode: (value: boolean) => void;
  /** Node ids seeded into a partial-template create (from a canvas selection), or null. */
  partialSeedIds: string[] | null;
  /** Enter the Templates view in create mode for a full-pipe template. */
  startCreateFull: () => void;
  /** Enter the Templates view in create mode seeded with a canvas selection. */
  startCreateFromSelection: (ids: string[]) => void;
  /** Leave create mode and clear any seeded selection. */
  exitCreateMode: () => void;
  pipeTemplates: UsePipeTemplatesResult;
  starterPipeTemplates: PipeTemplate[];
  /** Starter template the user picked for a new pipe (drives the welcome callout). */
  chosenTemplate: PipeTemplate | null;
  handleApplyStarterTemplate: (tpl: PipeTemplate) => void;
  handleApplyTemplateToPipe: (tpl: PipeTemplate) => void;
}

/**
 * View-selection + starter/templates wiring for the pipe editor: which
 * sidebar view is active (synced to `?tab=`), the new-pipe starter picker,
 * and applying a template snapshot into the form.
 */
export function usePipeTemplatesView(args: UsePipeTemplatesViewArgs): PipeTemplatesView {
  const { isNew, initialTab, setSearchParams, setFormData, setIsModified } = args;

  const [activeTab, setActiveTab] = useState<string>(() =>
    initialTab && VALID_VIEWS.includes(initialTab) ? initialTab : 'visual'
  );
  const [pipePickerShown, setPipePickerShown] = useState(isNew);
  const [applyingStarterId, setApplyingStarterId] = useState<string | null>(null);
  const [pickerExpandedId, setPickerExpandedId] = useState<string | null>(null);
  const [templatesCreateMode, setTemplatesCreateMode] = useState(false);
  const [partialSeedIds, setPartialSeedIds] = useState<string[] | null>(null);
  const [chosenTemplate, setChosenTemplate] = useState<PipeTemplate | null>(null);

  const pipeTemplates = usePipeTemplates();
  const starterPipeTemplates = useMemo(
    () =>
      sortPipeTemplatesForDisplay(
        // Starters seed a brand-new pipe, so only whole-pipe (full or
        // legacy untagged) templates qualify; partial item bundles are
        // applied to an existing pipe from the Templates view instead.
        // IDE-tagged starters belong to the `/ide/new` picker, not here.
        pipeTemplates.templates.filter(
          t =>
            t.kind !== 'partial' &&
            (t.tags ?? []).includes('starter') &&
            !(t.tags ?? []).includes('ide')
        )
      ),
    [pipeTemplates.templates]
  );

  const handleTabChange = useCallback(
    (key: string | null) => {
      if (key) {
        setActiveTab(key);
        setSearchParams({ tab: key }, { replace: true });
      }
    },
    [setSearchParams]
  );

  const toggleExpanded = useCallback((id: string) => {
    setPickerExpandedId(prev => (prev === id ? null : id));
  }, []);

  const applyTemplateToForm = useCallback(
    (tpl: PipeTemplate) => {
      // Partial templates merge their item bundle onto the current form;
      // full (and legacy untagged) templates replace the form from the
      // `pipe` snapshot (which carries canvas + variants for full kinds).
      if (tpl.kind === 'partial') {
        if (!Array.isArray(tpl.items) || tpl.items.length === 0) return;
        setFormData(prev => applyPipeTemplateItems(prev, tpl.items ?? []));
        setIsModified(true);
        return;
      }
      if (!tpl.pipe || typeof tpl.pipe !== 'object') return;
      // Full templates carry a `$SURFACE_ROUTE` placeholder that the resolver
      // substitutes with the form's current route — i.e. the resolved route
      // equals `prev.route`, which the access-point's `selectedPrefix` /
      // `customPath` already describe. Leave them intact: clearing them would
      // strand the canvas reseed (which waits for a parsed `route_prefix`)
      // and the saved canvas blob's rate-limit / juror decorations would
      // never render.
      setFormData(prev => {
        const resolved = resolvePipeTemplateBlob(tpl.pipe as Record<string, any>, {
          name: prev.name,
          route: prev.route,
          endpoint: prev.endpoint_url,
        });
        return { ...prev, ...resolved } as PipeFormData;
      });
      setIsModified(true);
    },
    [setFormData, setIsModified]
  );

  const handleApplyStarterTemplate = useCallback(
    (tpl: PipeTemplate) => {
      setApplyingStarterId(tpl.id);
      try {
        applyTemplateToForm(tpl);
        showPipeToast(
          'success',
          `Started from "${tpl.name}". Fill in any remaining fields and Save.`
        );
        setChosenTemplate(tpl);
        setPipePickerShown(false);
      } finally {
        setApplyingStarterId(null);
      }
    },
    [applyTemplateToForm]
  );

  const handleApplyTemplateToSurface = useCallback(
    (tpl: PipeTemplate) => {
      // Partial templates merge additively, so they never need an
      // overwrite confirmation; full templates replace the Surface.
      const confirmed =
        isNew ||
        tpl.kind === 'partial' ||
        window.confirm(
          `Applying "${tpl.name}" will overwrite this Surface configuration. Continue?`
        );
      if (!confirmed) return;
      applyTemplateToForm(tpl);
      setActiveTab('visual');
      showPipeToast('success', `Applied "${tpl.name}".`);
    },
    [applyTemplateToForm, isNew]
  );

  // Create-mode entry: a full-pipe capture, or seeded from a canvas selection.
  const startCreateFull = useCallback(() => {
    setPartialSeedIds(null);
    setTemplatesCreateMode(true);
    setActiveTab('templates');
  }, []);
  const startCreateFromSelection = useCallback((ids: string[]) => {
    setPartialSeedIds(ids.length > 0 ? ids : null);
    setTemplatesCreateMode(true);
    setActiveTab('templates');
  }, []);
  const exitCreateMode = useCallback(() => {
    setTemplatesCreateMode(false);
    setPartialSeedIds(null);
  }, []);

  // Leaving the Templates view always drops back to the list.
  useEffect(() => {
    if (activeTab !== 'templates' && templatesCreateMode) {
      setTemplatesCreateMode(false);
      setPartialSeedIds(null);
    }
  }, [activeTab, templatesCreateMode]);

  return {
    activeTab,
    setActiveTab,
    handleTabChange,
    pipePickerShown,
    setPipePickerShown,
    applyingStarterId,
    pickerExpandedId,
    toggleExpanded,
    templatesCreateMode,
    setTemplatesCreateMode,
    partialSeedIds,
    startCreateFull,
    startCreateFromSelection,
    exitCreateMode,
    pipeTemplates,
    starterPipeTemplates,
    chosenTemplate,
    handleApplyStarterTemplate,
    handleApplyTemplateToPipe: handleApplyTemplateToSurface,
  };
}
