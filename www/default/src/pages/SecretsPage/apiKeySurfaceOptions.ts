export interface ApiKeySurfaceOption {
  id: string;
  name: string;
}

type SurfaceLike = {
  id?: unknown;
  surface_id?: unknown;
  name?: unknown;
  status?: unknown;
};

const stringValue = (value: unknown): string => (typeof value === 'string' ? value.trim() : '');

export const apiKeySurfaceOptions = (items: SurfaceLike[]): ApiKeySurfaceOption[] =>
  items
    .map(item => {
      const id = stringValue(item.id) || stringValue(item.surface_id);
      if (!id) return null;
      return {
        id,
        name: stringValue(item.name) || id,
      };
    })
    .filter((item): item is ApiKeySurfaceOption => item !== null)
    .sort((a, b) => a.name.localeCompare(b.name));
