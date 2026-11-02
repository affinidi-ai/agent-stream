import { useCallback, useEffect, useRef, useState } from 'react';
import { apiClient } from '../../../api';
import type { integrationIntegration } from '../../../components/connection-points/IntegrationsStep';
import type { LLMProvider, PipeConfig, PipeFormData, RoutingConfig } from '../types';
import { EMPTY_PIPE_FORM } from '../types';
import { mapPipeToFormData } from '../pipeMappingHelpers';
import { getRandomWord } from '../../../utils/stringUtils';

export interface UsePipeFormArgs {
  pipeId?: string;
  llmProviders: LLMProvider[];
  routingConfig: RoutingConfig | null;
  /**
   * Fired right after a pipe loads, before its mapped form is committed.
   * The page uses it to seed the variant snapshot manager from the wire
   * pipe and may return the form to render in place of the bare base
   * (e.g. the default variant's resolved snapshot).
   */
  onPipeLoaded?: (pipe: PipeConfig, mapped: PipeFormData) => PipeFormData | void;
}

export interface PipeForm {
  formData: PipeFormData;
  setFormData: React.Dispatch<React.SetStateAction<PipeFormData>>;
  loading: boolean;
  isModified: boolean;
  setIsModified: (value: boolean) => void;
  integrations: integrationIntegration[];
  setIntegrations: React.Dispatch<React.SetStateAction<integrationIntegration[]>>;
  selectedPrefix: string;
  setSelectedPrefix: (value: string) => void;
  customPath: string;
  setCustomPath: (value: string) => void;
  /**
   * True once route→prefix parsing has been attempted against the routing
   * catalogue — even if no prefix matched (`selectedPrefix` stays `''`).
   * Lets a consumer (the canvas reseed gate) distinguish "still waiting on
   * the parse" from "parsed, but this route no longer matches any known
   * prefix" so it isn't stuck waiting forever for a match that will never
   * come.
   */
  routePrefixResolved: boolean;
  handleInputChange: (field: string, value: any) => void;
  reloadPipe: () => Promise<void>;
}

/**
 * Owns the pipe editor's form state plus the load lifecycle and route
 * parsing. Pure backend→form transforms live in `pipeMapping`; the save and
 * delete lifecycle lives in `usePipeSave`.
 */
export function usePipeForm(args: UsePipeFormArgs): PipeForm {
  const { pipeId, llmProviders, routingConfig, onPipeLoaded } = args;

  const [loading, setLoading] = useState(true);
  const [isModified, setIsModified] = useState(false);
  const [integrations, setIntegrations] = useState<integrationIntegration[]>([]);
  const [selectedPrefix, setSelectedPrefix] = useState<string>('');
  const [customPath, setCustomPath] = useState<string>('');
  const [routePrefixResolved, setRoutePrefixResolved] = useState(false);
  // Seed a new LLM Surface with a memorable default name at state-init time
  // so it is never nameless on the very first render (and an immediate Save
  // works). Editing or applying a template later preserves whatever name is
  // present. Existing pipes load their real name via `reloadPipe`.
  //
  // The same two words back both the default name and the auto-filled custom
  // path, so they always match. Generated once per editor instance.
  const defaultWordsRef = useRef<[string, string]>([getRandomWord(), getRandomWord()]);
  // Keep the latest load callback in a ref so `reloadPipe`'s identity
  // (depended on by an effect and `usePipeSave`) never churns when the
  // page passes a fresh closure each render.
  const onPipeLoadedRef = useRef(onPipeLoaded);
  onPipeLoadedRef.current = onPipeLoaded;
  const [formData, setFormData] = useState<PipeFormData>(() =>
    pipeId && pipeId !== 'new'
      ? EMPTY_PIPE_FORM
      : {
          ...EMPTY_PIPE_FORM,
          name: `surface-${defaultWordsRef.current[0]}-${defaultWordsRef.current[1]}`,
        }
  );

  const reloadPipe = useCallback(async () => {
    try {
      const response = await apiClient.fetch(`/api/v1/pipes/${pipeId}`);
      if (!response.ok) {
        throw new Error('Failed to load pipe');
      }
      const pipe: PipeConfig = await response.json();
      const { formData: mapped, integrations: loaded } = mapPipeToFormData(pipe, llmProviders);
      const overridden = onPipeLoadedRef.current?.(pipe, mapped);
      setFormData(overridden ?? mapped);
      if (loaded) {
        setIntegrations(loaded);
      }
      setIsModified(false);
    } catch (error) {
      console.error('Failed to load pipe:', error);
      alert('Failed to load pipe');
    } finally {
      setLoading(false);
    }
  }, [pipeId, llmProviders]);

  useEffect(() => {
    if (pipeId && pipeId !== 'new') {
      reloadPipe();
    } else {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pipeId]);

  // Auto-default a brand-new pipe's access point to the first host listener,
  // the first path prefix, and a memorable two-word path — mirroring the
  // agent surface's new-surface defaults. Runs once when the routing
  // catalogue arrives; existing pipes keep their persisted route.
  const seededDefaultsRef = useRef(false);
  useEffect(() => {
    if (pipeId && pipeId !== 'new') return;
    if (seededDefaultsRef.current || !routingConfig) return;
    const listener = routingConfig.available_listen_addresses?.[0] ?? '';
    const prefix = routingConfig.pipe_path_prefix?.[0]?.prefix ?? '';
    if (!listener && !prefix) return;
    seededDefaultsRef.current = true;
    const path = `${defaultWordsRef.current[0]}/${defaultWordsRef.current[1]}`;
    const route = prefix ? `${prefix}/${path}` : '';
    setSelectedPrefix(prefix);
    setCustomPath(path);
    setRoutePrefixResolved(true);
    setFormData(prev => ({ ...prev, listen_address: listener, route }));
  }, [pipeId, routingConfig]);

  // Parse route into prefix and custom path once routing config is ready.
  // A route that matches no known prefix (e.g. the prefix was since removed
  // from routing config, or the route came from an unresolved template
  // token) is a real, resolvable outcome — not a signal to keep waiting —
  // so `routePrefixResolved` is set regardless of whether a match was found.
  useEffect(() => {
    if (!pipeId || !formData.route || !routingConfig) {
      return;
    }
    if (routePrefixResolved) {
      return;
    }
    const route = formData.route;
    let parsedPrefix = '';
    let parsedCustomPath = '';
    if (route && routingConfig.pipe_path_prefix) {
      for (const prefixInfo of routingConfig.pipe_path_prefix) {
        if (route.startsWith(prefixInfo.prefix + '/')) {
          parsedPrefix = prefixInfo.prefix;
          parsedCustomPath = route.substring(prefixInfo.prefix.length + 1);
          break;
        }
      }
    }
    setSelectedPrefix(parsedPrefix);
    setCustomPath(parsedCustomPath);
    setRoutePrefixResolved(true);
  }, [pipeId, formData.route, routingConfig, routePrefixResolved]);

  const handleInputChange = useCallback((field: string, value: any) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    setIsModified(true);
  }, []);

  return {
    formData,
    setFormData,
    loading,
    isModified,
    setIsModified,
    integrations,
    setIntegrations,
    selectedPrefix,
    setSelectedPrefix,
    customPath,
    setCustomPath,
    routePrefixResolved,
    handleInputChange,
    reloadPipe,
  };
}
