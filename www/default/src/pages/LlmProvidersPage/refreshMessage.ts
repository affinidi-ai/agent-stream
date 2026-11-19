export type RefreshResponse =
  | {
      outcome: 'updated';
      version: string;
      publication_sequence: number;
      providers: number;
      added: number;
      backup: boolean;
    }
  | {
      outcome: 'unchanged';
      version: string;
      publication_sequence: number;
    };

export const refreshMessage = (response: RefreshResponse): string =>
  response.outcome === 'unchanged'
    ? `Built-in models are already up to date (catalog ${response.version}).`
    : `Built-in models refreshed to catalog ${response.version} — ${response.providers} providers, ${response.added} added disabled.`;
