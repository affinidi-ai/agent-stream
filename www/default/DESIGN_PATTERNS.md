# Dashboard Design Patterns — Cookbook (`www/default`)

A copy‑paste reference for the Agent Stream dashboard. Every reusable UI
pattern lives here with a ready snippet and the rules for it. Use it two ways:

- **Aligning an existing page** — “apply the standard **tab** / **badge** / **button** /
  **empty state** styling here.”
- **Building a new page** — “this page needs a **search bar**, **pill tabs**, and an
  **empty state**” and the pieces below compose into a working page.

> This file is the fast, snippet‑first cheat sheet; [`AGENTS.md`](./AGENTS.md) holds the
> working rules. Keep them in sync when a pattern changes.

---

## How to reference this file

Say the pattern name and the target. For example:

- “Add the **standard empty state** to the X tab.”
- “Give this page the **pill tabs** like Credentials.”
- “Use the **soft‑pill count badge** on this list header.”
- “Make this the **standard Add button** (md AppButton).”
- “Build a **standard list page**: search bar + card + table + empty state.”

---

## Golden rules (always)

1. **Reuse shared components** from `src/components/shared/` before writing markup.
2. **Colors:** CSS uses `var(--token)`; TSX/charts use `UI_COLORS`/`CHART_PALETTE` from
   `src/utils/uiPalette.ts`. Never raw hex.
3. **Gate writes** with `usePermissions()`; gate routes with `<ProtectedRoute>`.
4. **Dark theme:** every custom style needs a `body.dark-theme …` override.
5. **Filter client‑side** with `useMemo`.
6. **Never** show the internal code name “Agent Surface” in dashboard copy; users see
   **LLM Surface** and **IDE Surface** (`CONTEXT.md`).
7. **Presentational changes stay presentational** — don’t alter routing/data/logic while restyling.

---

## Quick reference

| Pattern              | Component / class                    | Import                               |
| -------------------- | ------------------------------------ | ------------------------------------ |
| Count / label badge  | `Badge` (soft pill)                  | `src/components/shared/Badge`        |
| Status chip          | raw `badge text-bg-*` (solid)        | —                                    |
| Button               | `AppButton`                          | `src/components/shared/AppButton`    |
| Empty state          | `EmptyState`                         | `src/components/shared/EmptyState`   |
| Search field         | `SearchInput`                        | `src/components/shared/SearchInput`  |
| Tabs (pills)         | `Tabs`/`Tab` + `custom-channel-tabs` | `react-bootstrap`                    |
| Destructive action   | `DeleteButton`                       | `src/components/shared/DeleteButton` |
| Docs / external link | `Link`                               | `src/components/shared/Link`         |

---

## 1. Page shell & layout

**When:** every page.

```tsx
<div className="container-fluid">
  {/* Page-level search bar — above the card */}
  <div className="d-sm-flex align-items-center justify-content-between mb-4">
    <SearchInput value={search} onChange={setSearch} placeholder="Filter..." width="384px" />
  </div>

  <div className="card shadow mb-4">
    <div className="card-header py-3 d-flex justify-content-between align-items-center">
      <h6 className="m-0 font-weight-bold text-primary">
        <i className="fas fa-icon"></i> Section Title <Badge value={count} className="ms-2" />
      </h6>
      {canEdit && (
        <AppButton
          variant="primary"
          size="md"
          iconStart={<i className="fas fa-plus fa-sm me-1" />}
        >
          Add Thing
        </AppButton>
      )}
    </div>
    <div className="card-body">{/* table / form / list */}</div>
  </div>
</div>
```

**Rules**

- **The search bar lives at page level** — in a `d-sm-flex align-items-center
  justify-content-between mb-4` row above the card, **not** inside the card-header.
- **The primary Add CTA lives in the `card-header`** (right side, next to the title +
  count). (Matches LLM Surfaces, IDE Surfaces, Prompts, Teams, Members.)
- When the list is empty, the Add CTA moves into the `EmptyState` (§6) **only if the
  card header is hidden in that state**; a single always‑visible card keeps its header
  CTA and omits the EmptyState CTA (see §6).
- Card header is `py-3` — don’t change its height; the `md` button sets the row height.
- Header title colour comes from `.card-header .m-0`/`h6` (accent‑blue) — don’t override.
- A **standalone** page with no card (e.g. a detail/editor) may use a top header row
  (`d-sm-flex justify-content-between mb-4`) with an `h1.h3` title left and the CTA right.

---

## 2. Search bar

**When:** any filterable list.

```tsx
import SearchInput from '../components/shared/SearchInput';

<SearchInput
  value={searchTerm}
  onChange={setSearchTerm}
  placeholder="Filter things..."
  width="384px"
/>;
```

**Rules**

- **Page-level placement by default** — sits in the `d-sm-flex mb-4` row above the card
  (see §1). Only place inside a card-header if explicitly required for a specific layout.
- Use `width="384px"` for page-level filter rows (the default `240px` is for compact/embedded use).
- Keep filtering client‑side (`useMemo` over the loaded list).

---

## 3. Tabs (pill buttons)

**When:** a page with multiple sub‑views.

```tsx
import { Tabs, Tab } from 'react-bootstrap';

<Tabs activeKey={activeTab} onSelect={/* url‑sync */} className="mb-3 custom-channel-tabs">
  <Tab
    eventKey="one"
    title={
      <>
        <i className="fas fa-icon"></i> One {tabBadge(oneCount)}
      </>
    }
  >
    …
  </Tab>
</Tabs>;
```

**Rules**

- `custom-channel-tabs` renders the tab row as **rounded pill buttons**. **Unselected**
  tabs are **full‑opacity muted chips** — never dimmed with `opacity` (in dark mode they
  use a **darker** chip so they recede without looking disabled). The **selected** tab is
  a **solid `--accent-blue` fill with white, weight‑600 text**, the **same treatment in
  both light and dark**, so it clearly reads as selected. Styling lives in `dashboard.css`.
- **Do not** wrap a tabbed page in a `card` — the tabs sit directly under the search bar.
- When a tab body is a component that is **also a standalone route** (e.g. Teams,
  Members), drop its inner `container-fluid` while embedded (gate on a `controlled`/
  `embedded` prop) so its content lines up with the tab row instead of picking up an
  extra gutter of padding.
- **Tab‑strip filter count** (`tabBadge`, shown only while searching) stays a **solid**
  dark‑blue badge (see 4c) — not the soft pill.

---

## 4. Badges

### 4a. Count / label — soft pill (default)

**When:** a count next to a **list header** (“Providers 3 of 12”) or a filter chip.

```tsx
import { Badge } from '../components/shared/Badge';

<Badge
  value={filtered.length}
  suffix={searchTerm ? ` of ${total.length}` : undefined}
  className="ms-2"
  ariaLabel={`${filtered.length} things`}
/>;
```

Props: `value`, `tone` (default `primary`), `size` (`sm`|`md`, default `md`),
`prefix`, `suffix`, `className`, `ariaLabel`. Renders `badge app-badge app-badge--{size} text-bg-{tone}`.

### 4b. Status chip — solid (keep as raw span)

**When:** a semantic status (Active / Expired / On / Off / protocol tag).

```tsx
<span className="badge text-bg-success">Active</span>
<span className="badge text-bg-warning">Expired (refreshable)</span>
<span className="badge text-bg-secondary me-1">scope</span>
```

**Rule:** status chips stay **solid** `text-bg-*`. Do **not** convert them to `<Badge>`.

### 4c. Tab‑strip filter count — solid

```tsx
const tabBadge = (count: number) => {
  if (!filterActive) return null; // only while searching
  return (
    <span className="badge text-bg-primary ms-2" style={{ verticalAlign: 'middle' }}>
      {count}
    </span>
  );
};
```

**Rule:** the count inside a pill tab is **solid dark blue**, and only shows while a
search filter is active.

---

## 5. Buttons

**When:** any action. Never hand‑roll `btn` markup with inline font/padding.

```tsx
import { AppButton } from '../components/shared/AppButton';

// Primary CTA (header “Add”, empty‑state CTA). md = standard header size.
<AppButton variant="primary" size="md" iconStart={<i className="fas fa-plus fa-sm me-1" />}>
  Add Thing
</AppButton>

// Secondary / inline row action
<AppButton variant="outline-secondary" size="sm">Edit</AppButton>

// Async
<AppButton variant="primary" loading={saving}>Save</AppButton>
```

Props: `variant` (default `primary`), `size` (`sm`|`md`, default `sm`), `loading`,
`loadingLabel`, `iconStart`, `iconEnd`, plus native button attrs.

**Rules**

- `variant="primary"` **auto‑adds `shadow-sm`** — don’t add it again.
- Header “Add” buttons use **`size="md"`** so header height matches across pages.
- Sizes: `.btn-sm` = `0.375rem 0.75rem / 0.875rem`; `.btn-md` = `0.5rem 1rem / 0.9375rem`.

---

## 6. Empty states

**Rule: _empty means focus, filled means act._** A list that has never had an item is
an onboarding moment, not a broken page. Strip everything that assumes content already
exists and give the user one obvious next step.

**When:** a list has no items, or a search matches nothing. These are **two different
states** — tell them apart by _total_ count vs _filtered_ count:

- **True‑empty** — nothing created yet (`items.length === 0`). Onboarding treatment.
- **Filtered‑empty** — items exist but the filter hid them all (`items.length > 0 &&
filtered.length === 0`). This is a search miss, **not** onboarding.

```tsx
import { EmptyState } from '../components/shared/EmptyState';

const isEmpty = items.length === 0; // nothing created yet
const onboarding = !loading && !error && isEmpty && !search; // empty AND not searching
const noMatch = !loading && !error && filtered.length === 0 && !onboarding; // search miss

/* Page-level search row (§1/§2): keep the search box on true-empty. */
<div className="d-sm-flex align-items-center justify-content-between mb-4">
  <SearchInput value={search} onChange={setSearch} placeholder="Filter things..." width="384px" />
</div>;

/* Header: hide the count badge and the Add CTA on true-empty. */
<div className="card-header py-3 d-flex justify-content-between align-items-center">
  <h6 className="m-0 font-weight-bold text-primary">
    <i className="fas fa-icon" /> Things
    {!isEmpty && <Badge value={items.length} className="ms-2" />}
  </h6>
  {canEdit && !isEmpty && (
    <AppButton
      variant="primary"
      size="md"
      iconStart={<i className="fas fa-plus fa-sm me-1" />}
      onClick={openAdd}
    >
      Add Thing
    </AppButton>
  )}
</div>;

/* Body A) onboarding — empty AND not searching: one centered block, Add CTA moved here. */
{
  onboarding && (
    <EmptyState
      icon="fa-icon"
      title="Add your first thing"
      body="One concise line."
      ctaLabel={canEdit ? 'Add Thing' : undefined}
      ctaIcon="fa-plus"
      onCtaClick={canEdit ? openAdd : undefined}
    />
  );
}

/* Body B) no-match — a search matched nothing. Small search block. It carries the
   primary CTA ONLY when the list is truly empty (header CTA is hidden then); when items
   exist the header Add is already visible, so no CTA here. */
{
  noMatch && (
    <div className="text-center text-muted py-5">
      <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
      <p className={isEmpty && canEdit ? 'mb-3' : 'mb-0'}>No things match your search.</p>
      {isEmpty && canEdit && (
        <AppButton
          variant="primary"
          size="md"
          iconStart={<i className="fas fa-plus fa-sm me-1" />}
          onClick={openAdd}
        >
          Add Thing
        </AppButton>
      )}
    </div>
  );
}
```

Props: `icon`, `title`, `body`, `ctaLabel`, `ctaIcon`, `onCtaClick`, `docsHref`,
`docsLabel` (default `View Docs`), `variant` (`inline` default | `overlay`).

**Rules**

- **Distinguish onboarding from a search miss.** Onboarding (the big block) shows only
  when the list is empty **and** no search/filter is active. Any search that matches
  nothing — whether the list is empty or just filtered — shows the small no‑match block.
- **On true‑empty, remove what has no meaning yet:** hide the header Add CTA (it moves
  into the block), hide the count badge (a count of zero is noise), and hide
  data‑dependent controls (e.g. the LLM Surfaces recency clock, the certificate‑kind
  filter). **Keep** the search box.
- **The onboarding block is:** large icon → **directive** title (`Add your first…`, never
  a dead `No X yet`) → **one** concise line → **one** primary CTA. Deeper explanation
  belongs in help/docs, not here.
- **The no‑match block carries the primary CTA only when the list is truly empty.** On a
  truly‑empty list the header Add is hidden, so the search‑miss block repeats the primary
  CTA (contextual copy: `No things match your search.`) so the user can still act. When
  items exist, the header Add is already visible, so the no‑match block shows **no** CTA.
- **The CTA is the page's main action moved down.** Add pages use the Add button; a
  read‑only log (e.g. Credential Delegation Audit) uses **Refresh**. A page with no user
  action (auto‑generated content, e.g. Credential Tokens) shows **no CTA** — icon +
  title + line only, so we never render a button that does nothing.
- CTA only renders when both `ctaLabel` **and** `onCtaClick` are set — gate on permission.
- **Once one item exists, flip back:** the header CTA and count return and the block
  disappears. The empty state is a one‑time doorway, not a persistent panel.
- **Exceptions:** monitoring dashboards that aren't CRUD lists (e.g. `TasksPage`) keep
  their summary widgets and header controls always on and don't apply this rule.
- Use `variant="overlay"` only for full‑canvas placeholders (e.g. Connections graph).

---

## 7. Data table (list)

```tsx
<div className="table-responsive">
  <table className="table table-hover table-sm" width="100%" cellSpacing="0">
    <thead>
      <tr>
        <th>Name</th>
        <th>Updated</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      {filtered.map(row => (
        <tr key={row.id} style={{ cursor: 'pointer' }} onClick={() => open(row)}>
          <td>{row.name}</td>
          <td title={row.updatedAtAbsolute}>{timeAgo(row.updatedAt)}</td>
          <td>{/* AppButton / DeleteButton */}</td>
        </tr>
      ))}
    </tbody>
  </table>
</div>
```

**Rules**

- Data‑heavy lists use `table table-hover table-sm`.
- Timestamps: relative text + absolute `title` tooltip (`timeAgo` / `formatDateTime`).
- **Row emphasis (unread / highlighted):** use a **subtle accent tint** on the row,
  **not** Bootstrap's `table-light` (which renders as a harsh light band in dark mode and
  turns white on hover). Give the row a dedicated class and tint it `rgba(74,144,226,…)`
  with a gentle matching hover in both themes (use the shared `.table-row--highlight`
  class — see the notifications list and the Settings → Users tab).

---

## 8. Loading & error

```tsx
{loading ? (
  <div className="text-center py-5"><div className="spinner-border text-primary" role="status" /></div>
) : error ? (
  <div className="alert alert-danger">
    <i className="fas fa-exclamation-triangle me-2" /> {error}
    <AppButton variant="outline-danger" size="sm" className="ms-3" onClick={reload}>Retry</AppButton>
  </div>
) : (
  /* content */
)}
```

Recommended branch order in a card body: **loading → error → empty → no‑results → list**.

- **Spinner goes _inside_ `card-body`, never in place of the whole card.** Render the
  card and its header immediately and swap only the body between loading/empty/list.
  Replacing the entire card with a centered spinner makes the card, header, and Add CTA
  pop in together when data lands, shifting the page.
- **Action-button headers use tight `0.5rem` vertical padding** (`dashboard.css`), so the
  `md` Add CTA sets the row height.

---

## 9. Destructive actions

```tsx
import { DeleteButton } from '../components/shared/DeleteButton';

<DeleteButton onDelete={() => remove(row.id)} />;
```

Use `DeleteButton` (built‑in confirm) — never a bare delete button.

---

## New page recipe

For a standard “list of things” page, compose the pieces:

1. **Shell** (§1): `container-fluid` → page-level **search** row (§2) → `card shadow mb-4`.
2. **Card header** (§1): `card-header py-3 d-flex justify-content-between align-items-center` —
   icon + title + soft‑pill **count** badge (§4a) on the left; the `md` primary **Add**
   button (§5) on the right.
3. **Body branches** (§8): loading → error → **empty state** (§6A, Add CTA moves here) →
   **no‑results** (§6B) → **table** (§7).
4. **Row actions:** `AppButton size="sm"` + `DeleteButton` (§9).
5. **Permissions:** wrap the route in `<ProtectedRoute>`, gate the Add/Edit/Delete on `usePermissions()`.

For a **tabbed** page, replace the single card with `Tabs className="custom-channel-tabs"`
(§3) directly under the search bar; each tab is its own card‑bodied list following the recipe.

---

## Fixed decisions (don’t relitigate)

- Two badge kinds are intentionally different — tab‑strip filter count **solid** (§4c),
  list‑header count **soft pill** (§4a).
- Status chips stay **solid** (§4b).
- Header (`card-header py-3`) and `.btn-md` keep their size — don’t shrink them.
- No `docsHref` / `DOCS_URL` on empty states — use the CTA path.

---

## Definition of done (for any UI change)

- `npm run lint` and `npm run typecheck` clean.
- Add a `.changelog/wip/<branch>.yaml` fragment (UX → `changed`/`fixed`; docs and refactors use the public category that matches their user-visible effect, or leave every list empty).
- If a **pattern** changed, update this file **and** `www/default/AGENTS.md` in the same change.
- Never run `git push`. Never edit `CHANGELOG.md` directly.
