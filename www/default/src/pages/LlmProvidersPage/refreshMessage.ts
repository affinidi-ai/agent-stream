export type RefreshResponse =
  | {
      outcome: 'updated';
      version: string;
      publication_sequence: number;
      providers: number;
      added: number;
      skipped: string[];
      backup: boolean;
    }
  | {
      outcome: 'unchanged';
      version: string;
      publication_sequence: number;
    };

export const refreshMessage = (response: RefreshResponse): string => {
  if (response.outcome === 'unchanged') {
    return `Built-in models are already up to date (catalog ${response.version}).`;
  }
  const refreshed = `Built-in models refreshed to catalog ${response.version} — ${response.providers} providers, ${response.added} added disabled.`;
  return response.skipped.length > 0
    ? `${refreshed} Skipped because a custom provider uses the same id: ${response.skipped.join(', ')}.`
    : refreshed;
};
