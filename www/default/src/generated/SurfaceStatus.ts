// Lifecycle status of an Agent Surface. Aliases the shared `EntityStatus`
// (members, teams, surfaces all share one `enabled | disabled | deleted` enum).

export type { EntityStatus as SurfaceStatus } from './EntityStatus';
