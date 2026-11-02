import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { apiClient, type PipeTemplate } from '../api';
import { showToast } from '../utils/toaster';
import { getRandomWord } from '../utils/stringUtils';
import { useApp } from '../context/AppContext';
import { SurfaceBuilder } from '../components/builder/SurfaceBuilder';
import ElementPalette from '../components/builder/ElementPalette';
import ElementsListTab from '../components/builder/ElementsListTab';
import PipeTemplatesPanel from '../components/builder/pipe-templates/PipeTemplatesPanel';
import { integrationIntegration } from '../components/connection-points/IntegrationsStep';
import PipeMonitoringTab from './EditPipePage/tabs/PipeMonitoringTab';
import PipeIntegrationsTab from './EditPipePage/tabs/PipeIntegrationsTab';
import { PipeConfigView } from './EditPipePage/PipeConfigView';
import { PipeManageActions } from './EditPipePage/PipeManageActions';
import { showPipeToast } from './EditPipePage/pipeToast';
import ConfigEditorFullscreen from '../components/builder/ConfigEditorFullscreen';
import IdeSandboxTab from './EditIdePage/IdeSandboxTab';
import { composeIdePayload } from './EditIdePage/idePayload';
import PipeFormShell, { type PipeShellView } from '../components/builder/PipeFormShell';
import PipeStarterPicker from './EditPipePage/PipeStarterPicker';
import {
  usePipeTemplates,
  sortPipeTemplatesForDisplay,
} from '../components/builder/pipe-templates/usePipeTemplates';
import {
  useSurfaceBuilder,
  type SurfaceBuilderState,
} from '../components/builder/hooks/useSurfaceBuilder';
import type { CanvasNode } from '../components/builder/SurfaceCanvas';
import {
  readCanvasSurfaceSize,
  readCanvasView,
  readCanvasSettings,
  registry,
} from '../components/builder/elements';
import { buildSurfaceContext } from '../components/builder/elements/surfaceContext';
import {
  SurfaceMetaProvider,
  type SurfaceMetaValue,
} from '../components/builder/SurfaceMetaContext';
import { usePipeDashboardSync } from './EditPipePage/hooks/usePipeDashboardSync';
import {
  IdePanelDataProvider,
  type IdeJwtStrategy,
  type IdeMemberPipe,
  type IdeOAuthIdentifier,
  type IdePolicyOption,
  type IdeProviderAuth,
  type IdeRoutingConfig,
} from '../components/builder/elements/ide/idePanelData';
import {
  IDE_SURFACE_SIZE,
  nodesFromIde,
  readIdeSource,
  composeIdeRoute,
  type IdeConfigLike,
} from '../components/builder/elements/ide/ideNodesFromConfig';
import {
  applyIdeTemplateItems,
  canSerializeIdeNode,
  describeIdeNode,
  serializeIdeTemplate,
} from '../components/builder/elements/ide/ideTemplateItems';
import type { TemplateNodeSerializer } from '../components/builder/pipe-templates/CreatePipeTemplateForm';

/** OpenAI-style providers carry the model in `model`; `custom` in `name`, Azure in `deployment_name`. */
function providerModelName(provider?: {
  model?: string;
  name?: string;
  deployment_name?: string;
}): string {
  return provider?.model || provider?.name || provider?.deployment_name || '';
}

/**
 * Seed a brand-new IDE surface's Access Point with the first available
 * listener + path prefix and a random custom path, so a fresh surface is
 * reachable without hunting for the listener config.
 */
function seedNewSourceDefaults(nodes: CanvasNode[], routing: IdeRoutingConfig): CanvasNode[] {
  const listen = routing.availableListenAddresses[0] ?? '';
  const prefix = routing.pathPrefixes[0]?.prefix ?? '';
  const customPath = `ide-${getRandomWord()}`.toLowerCase();
  return nodes.map(n =>
    n.id === 'ide-source'
      ? {
          ...n,
          configured: !!(listen && prefix && customPath),
          config: { ...(n.config ?? {}), listen_address: listen, prefix, custom_path: customPath },
        }
      : n
  );
}

const EditIdePage: React.FC = () => {
  const navigate = useNavigate();
  const { pipeId } = useParams<{ pipeId: string }>();
  const isNew = !pipeId || pipeId === 'new';
  const { state, actions } = useApp();

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [createdAt, setCreatedAt] = useState<string | null>(null);
  const [integrations, setIntegrations] = useState<integrationIntegration[]>([]);

  const [memberPipes, setMemberPipes] = useState<IdeMemberPipe[]>([]);
  const [routing, setRouting] = useState<IdeRoutingConfig | null>(null);
  const [strategies, setStrategies] = useState<IdeJwtStrategy[]>([]);
  const [providers, setProviders] = useState<IdeProviderAuth[]>([]);
  const [oauthIdentifiers, setOauthIdentifiers] = useState<IdeOAuthIdentifier[]>([]);
  const [policies, setPolicies] = useState<IdePolicyOption[]>([]);
  const [loadedConfig, setLoadedConfig] = useState<IdeConfigLike | null>(null);

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [isModified, setIsModified] = useState(false);
  const [hydrated, setHydrated] = useState(false);
  const [activeView, setActiveView] = useState('visual');
  const [templatesCreateMode, setTemplatesCreateMode] = useState(false);
  const [editorNodeId, setEditorNodeId] = useState<string | null>(null);

  const canvasViewRef = useRef<{ x: number; y: number; k: number } | null>(null);
  const canvasSettingsRef = useRef<{ hide_disabled: boolean } | null>(null);

  const builder = useSurfaceBuilder<SurfaceBuilderState>(
    { nodes: [], selectedNodeId: null, surfaceSize: { ...IDE_SURFACE_SIZE } },
    { onCommit: () => setIsModified(true) }
  );

  // New-surface starter picker (mirrors the LLM `/llm/new` flow): a new IDE
  // surface first shows the shared `PipeStarterPicker` before dropping onto the
  // canvas. Only IDE-tagged starters are offered here.
  const pipeTemplates = usePipeTemplates();
  const [pickerShown, setPickerShown] = useState(isNew);
  const [applyingStarterId, setApplyingStarterId] = useState<string | null>(null);
  const [pickerExpandedId, setPickerExpandedId] = useState<string | null>(null);
  const [starterConfig, setStarterConfig] = useState<IdeConfigLike | null>(null);

  const ideStarterTemplates = useMemo(
    () =>
      sortPipeTemplatesForDisplay(
        pipeTemplates.templates.filter(
          t =>
            t.kind !== 'partial' &&
            (t.tags ?? []).includes('starter') &&
            (t.tags ?? []).includes('ide')
        )
      ),
    [pipeTemplates.templates]
  );

  const toggleExpanded = useCallback((id: string) => {
    setPickerExpandedId(prev => (prev === id ? null : id));
  }, []);

  const handleApplyStarter = useCallback((tpl: PipeTemplate) => {
    setApplyingStarterId(tpl.id);
    try {
      const cfg = tpl.pipe && typeof tpl.pipe === 'object' ? (tpl.pipe as IdeConfigLike) : null;
      setStarterConfig(cfg);
      showToast('success', `Started from "${tpl.name}". Configure the catalogue and Save.`);
      setPickerShown(false);
    } finally {
      setApplyingStarterId(null);
    }
  }, []);

  const handleStartBlank = useCallback(() => {
    setStarterConfig(null);
    setPickerShown(false);
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const [routingRes, pipesRes, oneRes, strategiesRes, configRes, oauthRes, policiesRes] =
          await Promise.all([
            apiClient.fetch('/api/v1/config/surface-routing'),
            apiClient.fetch('/api/v1/pipes'),
            !isNew && pipeId
              ? apiClient.fetch(`/api/v1/pipes/${pipeId}`)
              : Promise.resolve(null as Response | null),
            apiClient.fetch('/api/v1/jwt-verification-strategies'),
            apiClient.fetch('/api/v1/pipes/config'),
            apiClient.fetch('/api/v1/oauth-identifiers'),
            apiClient.fetch('/api/v1/policy-definitions?policy_type=ide'),
          ]);

        let routingCfg: IdeRoutingConfig = { availableListenAddresses: [], pathPrefixes: [] };
        if (routingRes.ok) {
          const r = await routingRes.json();
          routingCfg = {
            availableListenAddresses: Array.isArray(r.available_listen_addresses)
              ? r.available_listen_addresses
              : [],
            pathPrefixes: Array.isArray(r.pipe_path_prefix) ? r.pipe_path_prefix : [],
          };
        }

        let members: IdeMemberPipe[] = [];
        if (pipesRes.ok) {
          const all = await pipesRes.json();
          members = (Array.isArray(all) ? all : [])
            .filter((p: any) => p?.pipe_type?.type === 'llm' && p?.status !== 'deleted')
            .map((p: any) => ({
              id: p.id,
              name: p.name,
              route: p.route,
              provider: p.pipe_type?.provider?.provider_type,
              model: providerModelName(p.pipe_type?.provider),
              variants: Array.isArray(p.variants)
                ? p.variants
                    .filter((v: any) => v && v.alias)
                    .map((v: any) => ({ alias: v.alias, name: v.name ?? v.alias }))
                : [],
            }));
        }

        let editConfig: IdeConfigLike | null = null;
        if (oneRes && oneRes.ok) {
          editConfig = await oneRes.json();
        }

        let strategyList: IdeJwtStrategy[] = [];
        if (strategiesRes.ok) {
          const raw = await strategiesRes.json();
          strategyList = (Array.isArray(raw) ? raw : [])
            .filter((s: any) => s && typeof s.id === 'string')
            .map((s: any) => ({
              id: s.id,
              name: typeof s.name === 'string' ? s.name : s.id,
              expected_issuer:
                typeof s.expected_issuer === 'string' ? s.expected_issuer : undefined,
            }));
        }

        let providerList: IdeProviderAuth[] = [];
        if (configRes.ok) {
          const cfg = await configRes.json();
          providerList = (Array.isArray(cfg?.llm?.providers) ? cfg.llm.providers : [])
            .filter((p: any) => p && typeof p.enum_value === 'string' && p.sandbox_auth)
            .map((p: any) => ({
              enum_value: p.enum_value,
              name: typeof p.name === 'string' ? p.name : p.enum_value,
              sandbox_auth: p.sandbox_auth,
            }));
        }

        let oauthList: IdeOAuthIdentifier[] = [];
        if (oauthRes.ok) {
          const raw = await oauthRes.json();
          oauthList = (Array.isArray(raw) ? raw : [])
            .filter((o: any) => o && typeof o.id === 'string')
            .map((o: any) => ({
              id: o.id,
              name: typeof o.name === 'string' ? o.name : o.id,
              provider: typeof o.provider === 'string' ? o.provider : 'oidc',
            }));
        }

        let policyList: IdePolicyOption[] = [];
        if (policiesRes.ok) {
          const raw = await policiesRes.json();
          policyList = (Array.isArray(raw) ? raw : [])
            .filter((p: any) => p && typeof p.id === 'string')
            .map((p: any) => ({
              id: p.id,
              name: typeof p.name === 'string' ? p.name : p.id,
              description: typeof p.description === 'string' ? p.description : '',
            }));
        }

        if (cancelled) return;
        setRouting(routingCfg);
        setMemberPipes(members);
        setStrategies(strategyList);
        setProviders(providerList);
        setOauthIdentifiers(oauthList);
        setPolicies(policyList);
        if (editConfig) {
          setLoadedConfig(editConfig);
          setName(editConfig.name ?? '');
          setDescription(editConfig.description ?? '');
          setEnabled((editConfig as { status?: string }).status !== 'disabled');
          setCreatedAt((editConfig as { created_at?: string }).created_at ?? null);
          const loadedIntegrations = (editConfig as { integrations?: integrationIntegration[] })
            .integrations;
          setIntegrations(Array.isArray(loadedIntegrations) ? loadedIntegrations : []);
        }
      } catch {
        if (!cancelled) {
          showToast('error', 'Failed to load IDE surface');
          setRouting(prev => prev ?? { availableListenAddresses: [], pathPrefixes: [] });
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [isNew, pipeId]);

  // Seed the canvas once routing (and, when editing, the saved config) have
  // loaded. Runs exactly once via the ref guard; a `replaceCommit` bakes the
  // seed in as the undo baseline so it never registers as an unsaved edit.
  const hydratedRef = useRef(false);
  useEffect(() => {
    if (hydratedRef.current) return;
    if (!routing) return;
    // A brand-new surface waits for the starter picker to be dismissed (via a
    // template pick or "start blank") before seeding the canvas.
    if (isNew && pickerShown) return;
    if (!isNew && !loadedConfig) return;
    hydratedRef.current = true;

    const cfg = isNew ? starterConfig : loadedConfig;
    let nodes = nodesFromIde(cfg, routing);
    if (isNew) nodes = seedNewSourceDefaults(nodes, routing);

    const savedSize = cfg ? readCanvasSurfaceSize(cfg) : null;
    const savedView = cfg ? readCanvasView(cfg) : null;
    const savedSettings = cfg ? readCanvasSettings(cfg) : null;
    if (savedView) canvasViewRef.current = savedView;
    canvasSettingsRef.current = savedSettings ?? { hide_disabled: false };

    builder.setState(prev => ({
      ...prev,
      nodes,
      selectedNodeId: null,
      surfaceSize: savedSize
        ? { w: savedSize.width, h: savedSize.height }
        : { ...IDE_SURFACE_SIZE },
    }));
    builder.replaceCommit();
    builder.bumpExternalRevision();
    setHydrated(true);
  }, [routing, loadedConfig, isNew, pickerShown, starterConfig, builder]);

  // Block save when any active canvas node is incomplete or invalid, pointing
  // the user at the first offending node — mirrors the LLM surface's save gate
  // so the toast and its "Show me" jump behave identically. Iterating the
  // registry (not a few hardcoded checks) also catches validation faults the
  // canvas already marks invalid, e.g. a malformed Access Point path.
  const getBlockingReason = useCallback((): { message: string; nodeId?: string } | null => {
    const nodes = builder.state.nodes;
    // Supply the live LLM-Surface registry so broken-link dependency errors
    // (a catalogue member whose surface was deleted) block Save, matching the
    // canvas's marching-ants ring.
    const availableSurfaces = memberPipes.map(p => ({
      id: p.id,
      type: 'llm-surface',
      name: p.name,
    }));
    const ctx = buildSurfaceContext('a2a', nodes, undefined, availableSurfaces);
    for (const node of nodes) {
      const reason = registry.getFaultReason(node.type, node.config);
      if (reason) {
        const label = registry.get(node.type)?.label ?? node.label ?? node.type;
        return { message: `${label}: ${reason}`, nodeId: node.id };
      }
      const depError = registry
        .getDependencyWarnings(node.type, node.config, ctx)
        .find(w => w.severity === 'error');
      if (depError) {
        const label = registry.get(node.type)?.label ?? node.label ?? node.type;
        return { message: `${label}: ${depError.message}`, nodeId: node.id };
      }
    }
    return null;
  }, [builder.state.nodes, memberPipes]);

  // Reveal the offending node on the canvas (drives the blocking toast's
  // "Show me") — select it so its side panel opens and switch to the Surface
  // view, exactly like the LLM surface's `showNode`.
  const showNode = useCallback(
    (nodeId: string) => {
      builder.handleNodeClick(nodeId);
      setActiveView('visual');
    },
    [builder]
  );

  const handleSave = useCallback(async () => {
    if (saving) return;
    if (!name.trim()) {
      showToast('warning', 'Enter a name for this IDE surface.');
      return;
    }
    const blocking = getBlockingReason();
    if (blocking) {
      showPipeToast(
        'error',
        blocking.message,
        blocking.nodeId
          ? { label: 'Show me', onClick: () => showNode(blocking.nodeId!) }
          : undefined
      );
      return;
    }

    setSaving(true);
    try {
      const nodes = builder.state.nodes;
      const id = isNew ? crypto.randomUUID() : pipeId!;
      const nextCreatedAt = isNew
        ? new Date().toISOString()
        : (createdAt ?? new Date().toISOString());

      const payload = composeIdePayload({
        id,
        nodes,
        surfaceSize: builder.state.surfaceSize,
        view: canvasViewRef.current,
        settings: canvasSettingsRef.current,
        name,
        description,
        enabled,
        integrations,
        createdAt: nextCreatedAt,
      });

      const res = await apiClient.fetch(isNew ? '/api/v1/pipes' : `/api/v1/pipes/${id}`, {
        method: isNew ? 'POST' : 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (res.ok) {
        showToast('success', isNew ? 'IDE surface created' : 'IDE surface saved');
        setIsModified(false);
        setCreatedAt(nextCreatedAt);
        if (isNew) navigate(`/ide/${id}`);
      } else {
        const err = await res.json().catch(() => ({}));
        showToast('error', `Failed to save: ${err.error || res.statusText}`);
      }
    } catch {
      showToast('error', 'Failed to save IDE surface');
    } finally {
      setSaving(false);
    }
  }, [
    saving,
    name,
    description,
    enabled,
    isNew,
    pipeId,
    createdAt,
    integrations,
    getBlockingReason,
    showNode,
    builder.state.nodes,
    builder.state.surfaceSize,
    navigate,
  ]);

  const handleDelete = useCallback(async () => {
    if (isNew || !pipeId) return;
    try {
      const res = await apiClient.fetch(`/api/v1/pipes/${pipeId}`, { method: 'DELETE' });
      if (res.ok) {
        showToast('success', 'IDE surface deleted');
        navigate('/ide');
      } else {
        const err = await res.json().catch(() => ({}));
        showToast('error', `Failed to delete: ${err.error || res.statusText}`);
      }
    } catch {
      showToast('error', 'Failed to delete IDE surface');
    }
  }, [isNew, pipeId, navigate]);

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

  const headerBadges = (
    <span className={`badge ms-2 ${enabled ? 'bg-success' : 'bg-secondary'}`}>
      {enabled ? 'Enabled' : 'Disabled'}
    </span>
  );

  const ideSurfaceMeta: SurfaceMetaValue = useMemo(
    () => ({
      variant: 'ide',
      name,
      description,
      tagsCsv: '',
      status: enabled ? 'enabled' : 'disabled',
      protocol: 'a2a',
      publishToDid: false,
      didwebvh: {
        enabled: false,
        auto_create: true,
        identity_id: '',
        did_path: '',
        injection_mode: 'header',
      },
      readOnly: false,
      protocolLocked: true,
      isCreate: isNew,
      surfaceId: isNew ? undefined : pipeId,
      setName: (v: string) => {
        setName(v);
        setIsModified(true);
      },
      setDescription: (v: string) => {
        setDescription(v);
        setIsModified(true);
      },
      setTagsCsv: () => {},
      setStatus: (v: 'enabled' | 'disabled' | 'deleted') => {
        setEnabled(v !== 'disabled');
        setIsModified(true);
      },
      setProtocol: () => {},
      setPublishToDid: () => {},
      setDidwebvh: () => {},
    }),
    [name, description, enabled, isNew, pipeId]
  );

  usePipeDashboardSync(isNew ? undefined : pipeId, activeView, state, actions);

  // Live wire payload for the Config tab — the exact JSON that Save would
  // persist, rebuilt from the canvas so it reflects unsaved edits and can be
  // copied into another surface's Config tab.
  const liveIdeConfig = useMemo(
    () =>
      composeIdePayload({
        id: isNew ? '' : (pipeId ?? ''),
        nodes: builder.state.nodes,
        surfaceSize: builder.state.surfaceSize,
        view: canvasViewRef.current,
        settings: canvasSettingsRef.current,
        name,
        description,
        enabled,
        integrations,
        createdAt: createdAt ?? '',
      }),
    [
      isNew,
      pipeId,
      builder.state.nodes,
      builder.state.surfaceSize,
      name,
      description,
      enabled,
      integrations,
      createdAt,
    ]
  );

  // Apply a pasted/edited IDE configuration into the editor. Reseeds the canvas
  // from the imported catalogue while preserving this surface's listener/route,
  // and imports the name/description/status. The user saves to persist.
  const handleApplyConfig = useCallback(
    (parsed: unknown): string | null => {
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return 'Configuration must be a JSON object';
      }
      if (!routing) return 'Routing configuration is still loading — try again in a moment.';
      const c = parsed as Record<string, unknown>;
      const currentSrc = readIdeSource(builder.state.nodes);
      const seeded = nodesFromIde(parsed as IdeConfigLike, routing);
      const nodes = seeded.map(n =>
        n.id === 'ide-source'
          ? {
              ...n,
              configured: !!(
                currentSrc.listen_address &&
                currentSrc.prefix &&
                currentSrc.custom_path
              ),
              config: {
                ...(n.config ?? {}),
                listen_address: currentSrc.listen_address,
                prefix: currentSrc.prefix,
                custom_path: currentSrc.custom_path,
              },
            }
          : n
      );
      builder.setState(prev => ({ ...prev, nodes, selectedNodeId: null }));
      builder.bumpExternalRevision();
      if (typeof c.name === 'string') setName(c.name);
      if (typeof c.description === 'string') setDescription(c.description);
      if (c.status === 'disabled') setEnabled(false);
      else if (c.status === 'enabled') setEnabled(true);
      setIsModified(true);
      return null;
    },
    [routing, builder]
  );

  const manageActions = (
    <PipeManageActions
      saving={saving}
      isModified={isModified}
      isNew={isNew}
      onSave={handleSave}
      onDelete={handleDelete}
      onClose={() => {
        if (isModified) {
          if (!window.confirm('You have unsaved changes. Are you sure you want to close?')) return;
        }
        navigate('/ide');
      }}
      entityLabel="IDE surface"
    />
  );

  if (loading) {
    return (
      <div className="container-fluid surface-page-fill">
        <div
          className="d-flex justify-content-center align-items-center"
          style={{ minHeight: 320 }}
        >
          <i className="fas fa-spinner fa-spin fa-2x text-muted" />
        </div>
      </div>
    );
  }

  if (isNew && pickerShown) {
    return (
      <PipeStarterPicker
        templates={ideStarterTemplates}
        loading={pipeTemplates.loading}
        error={pipeTemplates.error}
        applyingStarterId={applyingStarterId}
        expandedId={pickerExpandedId}
        onToggleExpand={toggleExpanded}
        onApply={handleApplyStarter}
        onCancel={() => navigate('/ide')}
        onStartBlank={handleStartBlank}
      />
    );
  }

  if (!hydrated) {
    return (
      <div className="container-fluid surface-page-fill">
        <div
          className="d-flex justify-content-center align-items-center"
          style={{ minHeight: 320 }}
        >
          <i className="fas fa-spinner fa-spin fa-2x text-muted" />
        </div>
      </div>
    );
  }

  const shellViews: PipeShellView[] = [
    { key: 'visual', label: 'Surface', icon: 'diagram-project' },
    { key: 'elements', label: 'Elements', icon: 'list' },
    { key: 'templates', label: 'Templates', icon: 'layer-group' },
    { key: 'monitoring', label: 'Monitoring', icon: 'chart-line', available: !isNew },
    {
      key: 'integrations',
      label: 'Integrations',
      icon: 'puzzle-piece',
      available: !isNew,
    },
    { key: 'sandbox', label: 'Sandbox', icon: 'flask', available: !isNew },
    { key: 'config', label: 'Config', icon: 'code' },
  ];

  const editorNode = editorNodeId
    ? (builder.state.nodes.find(n => n.id === editorNodeId) ?? null)
    : null;

  const openEditor = (id: string) => {
    setEditorNodeId(id);
    setActiveView('editor');
  };

  const closeEditor = () => {
    setEditorNodeId(null);
    setActiveView('visual');
  };

  if (editorNode) {
    shellViews.push({
      key: 'editor',
      label: registry.get(editorNode.type)?.label || 'Editor',
      icon: 'pen-to-square',
      onClose: closeEditor,
    });
  }

  const ideTemplateFilter = (t: PipeTemplate) => (t.tags ?? []).includes('ide');

  // Snapshot the composed IDE wire config into a portable template `pipe` blob,
  // dropping per-instance identity/routing (matching the builtin IDE templates,
  // which carry only `pipe_type` + governance and are applied via `nodesFromIde`).
  const ideTemplateBlob = (cfg: Record<string, any>): Record<string, any> => {
    const blob = { ...cfg };
    for (const field of [
      'id',
      'name',
      'description',
      'status',
      'listen_address',
      'route',
      'integrations',
      'canvas',
      'created_at',
      'updated_at',
    ]) {
      delete blob[field];
    }
    return blob;
  };

  // Partial IDE templates capture the front-door governance singletons
  // (Caller Context / OPA Policy / Rate Limit) instead of the LLM `pipe-*` nodes.
  const ideTemplateSerializer: TemplateNodeSerializer = {
    canSerialize: canSerializeIdeNode,
    serialize: serializeIdeTemplate,
    describe: describeIdeNode,
  };

  const renderActiveView = () => {
    switch (activeView) {
      case 'elements':
        return (
          <div className="p-3">
            <ElementsListTab
              nodes={builder.state.nodes}
              onSelectNode={id => {
                builder.handleNodeClick(id);
                setActiveView('visual');
              }}
            />
          </div>
        );
      case 'config':
        return <PipeConfigView config={liveIdeConfig} onApply={handleApplyConfig} />;
      case 'templates':
        return (
          <PipeTemplatesPanel
            onApplyTemplate={(tpl: PipeTemplate) => {
              if (tpl.kind === 'partial') {
                // Additive governance bundle: merge its items onto the live
                // canvas (replacing same-type singletons), then re-layout so the
                // new element seats on the source→catalogue edge.
                builder.setState(prev => ({
                  ...prev,
                  nodes: applyIdeTemplateItems(prev.nodes, tpl.items ?? []),
                  selectedNodeId: null,
                }));
                builder.handleAutoLayout();
                setIsModified(true);
                setActiveView('visual');
                showToast('success', `Applied "${tpl.name}".`);
                return;
              }
              const cfg =
                tpl.pipe && typeof tpl.pipe === 'object' ? (tpl.pipe as IdeConfigLike) : null;
              const seeded = nodesFromIde(cfg, routing ?? undefined);
              builder.setState(prev => ({ ...prev, nodes: seeded, selectedNodeId: null }));
              builder.bumpExternalRevision();
              setIsModified(true);
              setActiveView('visual');
              showToast('success', `Applied "${tpl.name}".`);
            }}
            currentPipe={liveIdeConfig}
            nodes={builder.state.nodes}
            createMode={templatesCreateMode}
            onExitCreateMode={() => setTemplatesCreateMode(false)}
            templateFilter={ideTemplateFilter}
            buildFullBlob={ideTemplateBlob}
            requiredTags={['ide']}
            serializer={ideTemplateSerializer}
          />
        );
      case 'monitoring':
        return !isNew && pipeId ? (
          <PipeMonitoringTab pipeId={pipeId} pipeName={name} state={state} actions={actions} />
        ) : (
          <div className="p-4 text-center text-muted">
            <i className="fas fa-chart-line fa-2x mb-2 d-block" />
            Monitoring data appears after the IDE surface is saved.
          </div>
        );
      case 'integrations':
        return !isNew && pipeId ? (
          <PipeIntegrationsTab
            pipeId={pipeId}
            integrations={integrations}
            onIntegrationsChange={(newIntegrations: integrationIntegration[]) => {
              setIntegrations(newIntegrations);
              setIsModified(true);
            }}
            isModified={isModified}
            isSaving={saving}
          />
        ) : null;
      case 'sandbox':
        return !isNew && pipeId ? (
          <IdeSandboxTab
            pipeId={pipeId}
            route={composeIdeRoute(
              readIdeSource(builder.state.nodes).prefix,
              readIdeSource(builder.state.nodes).custom_path
            )}
            nodes={builder.state.nodes}
            isModified={isModified}
          />
        ) : null;
      case 'editor':
        return editorNode ? (
          <IdePanelDataProvider
            value={{
              memberPipes,
              routing: routing!,
              strategies,
              providers,
              oauthIdentifiers,
              policies,
            }}
          >
            <div className="surface-builder-fullscreen">
              <ConfigEditorFullscreen
                node={editorNode}
                protocol="a2a"
                allNodes={builder.state.nodes}
                onUpdate={builder.handleNodeUpdate}
                onCloseFullscreenEditor={closeEditor}
              />
            </div>
          </IdePanelDataProvider>
        ) : null;
      default:
        return null;
    }
  };

  return (
    <div className="container-fluid surface-page-fill">
      <PipeFormShell
        pipeName={isNew ? 'New IDE Surface' : name || 'IDE Surface'}
        headerBadges={headerBadges}
        views={shellViews}
        activeView={activeView}
        onSelectView={setActiveView}
        canvasViewKey="visual"
        templateViewKey="templates"
        onCreateTemplate={() => {
          setActiveView('templates');
          setTemplatesCreateMode(true);
        }}
        manageActions={manageActions}
        paletteSlot={
          <ElementPalette
            variant="inline"
            scope="ide"
            protocol="a2a"
            existingNodes={builder.state.nodes}
            onAnyDragStart={() => setActiveView('visual')}
          />
        }
        canvas={
          <SurfaceMetaProvider value={ideSurfaceMeta}>
            <IdePanelDataProvider
              value={{
                memberPipes,
                routing: routing!,
                strategies,
                providers,
                oauthIdentifiers,
                policies,
              }}
            >
              <SurfaceBuilder
                builder={builder}
                surfaceName={name || 'IDE Surface'}
                protocol="a2a"
                scope="ide"
                canvasViewRef={canvasViewRef}
                canvasSettingsRef={canvasSettingsRef}
                initialHideDisabled={canvasSettingsRef.current?.hide_disabled ?? false}
                onOpenFullscreenEditor={openEditor}
              />
            </IdePanelDataProvider>
          </SurfaceMetaProvider>
        }
      >
        {renderActiveView()}
      </PipeFormShell>
    </div>
  );
};

export default EditIdePage;
