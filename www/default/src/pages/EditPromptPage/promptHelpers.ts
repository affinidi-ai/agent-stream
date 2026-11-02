import type { EntityStatus } from '../../generated/EntityStatus';

/** One chat message in a prompt version; `content` may contain `{{variables}}`. */
export interface PromptMessage {
  role: string;
  content: string;
}

/** One immutable version of a prompt. */
export interface PromptVersion {
  version: number;
  messages: PromptMessage[];
  label?: string | null;
  created_at?: string;
}

/** A named, versioned prompt template. */
export interface Prompt {
  id: string;
  name: string;
  description?: string | null;
  status: EntityStatus;
  versions: PromptVersion[];
  default_version?: number | null;
  created_at?: string;
  updated_at?: string;
}

export const EMPTY_PROMPT = (): Prompt => ({
  id: '',
  name: '',
  description: '',
  status: 'enabled',
  versions: [
    {
      version: 1,
      messages: [{ role: 'system', content: 'You are a helpful assistant.' }],
      label: '',
    },
  ],
  default_version: null,
});

/** Distinct `{{variable}}` names referenced across a version's messages. */
export const versionVariables = (version: PromptVersion | undefined): string[] => {
  if (!version) return [];
  const names: string[] = [];
  const re = /\{\{\s*([^}]+?)\s*\}\}/g;
  for (const msg of version.messages) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(msg.content)) !== null) {
      const name = m[1].trim();
      if (name && !names.includes(name)) names.push(name);
    }
  }
  return names;
};

export const promptLabel = (prompt: Prompt): string => prompt.name?.trim() || prompt.id;

/** Next unused version number for a prompt. */
export const nextVersionNumber = (prompt: Prompt): number =>
  prompt.versions.reduce((max, v) => Math.max(max, v.version), 0) + 1;

/** Validate a caller-supplied prompt id (1–128 chars, `[A-Za-z0-9_-]`). */
export const isValidPromptId = (id: string): boolean => /^[A-Za-z0-9_-]{1,128}$/.test(id);
