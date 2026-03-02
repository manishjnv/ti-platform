# IntelWatch — Development Instructions

## 3D Design System

The entire UI uses a consistent 3D depth effect to give cards, buttons, and icons a raised, tactile feel.

### CSS Utility Classes (defined in `globals.css`)

| Class | Usage | Effect |
|-------|-------|--------|
| `card-3d` | All `<Card>`, stat cards, panels | Multi-layer box-shadow with inset top highlight; lifts on hover |
| `icon-btn-3d` | Clickable action icon buttons | Raised pill with shadow; lifts on hover, depresses on click |
| `conn-badge-3d` | Connections count badge (non-clickable) | Inset shadow giving a sunken/recessed look |

### Card Component

The base `<Card>` component (`ui/card.tsx`) uses `card-3d` instead of plain `shadow-sm`. Every card in the project automatically gets 3D depth — no per-page overrides needed.

### StatCard

Dashboard stat cards use `card-3d` plus their existing gradient overlays. Icon containers use `text-muted-foreground/60` for visibility.

---

## Action Icons

Every intel item, IOC, or entity card/row should include the standard action icons described below.
Follow this guide when adding new pages or features that display intel or IOC data.

### Standard Icon Set

| Icon | Lucide Name | Default Color | Hover Color | Purpose | Clickable |
|------|-------------|---------------|-------------|---------|-----------|
| **Hunt** | `Crosshair` | `text-blue-400` | `text-blue-300` | Search local + internet | Yes |
| **Investigate** | `Telescope` | `text-purple-400` | `text-purple-300` | Relationship graph | Yes |
| **Connections** | `Share2` | `text-teal-400/70` | — | Show relation count | No |
| **Enrich** | `Zap` | `text-yellow-400` | `text-yellow-300` | Enrich via VT/Shodan | Yes |
| **Copy** | `Copy`/`Check` | `text-muted-foreground` | `text-foreground` | Copy to clipboard | Yes |

### Design Rules

1. **Always-on accent color** — Icons show their accent color at rest (not grey). They brighten on hover.
2. **3D pill buttons** — All clickable icons use the `icon-btn-3d` CSS class. This gives raised depth with shadow.
3. **Hover lift** — Buttons lift 1px on hover (`translateY(-1px)`) with stronger shadow.
4. **Press effect** — On `:active`, buttons sink back down with inset shadow.
5. **Connections badge** — Uses `conn-badge-3d` class (inset/sunken effect). Not clickable.
6. **Size** — Icons are `h-3.5 w-3.5` in tables, `h-3 w-3` in card meta rows.
7. **Labels** — On IntelCard, Hunt and Investigate show a `text-[10px] font-medium` label. Tables use icon-only.
8. **Group hover** — Use named groups (`group/hunt`, `group/inv`, etc.) so the icon brightens when hovering the button container.

### Where Icons Appear

| Page | Component | Layout | Icons Shown |
|------|-----------|--------|-------------|
| **Threat Feed** (`/threats`) | Inline cards | Vertical stack (right side) | Hunt, Investigate, Connections, ChevronRight |
| **Intel Items** (`/intel`) | `IntelCard.tsx` | Horizontal row (meta bar, right-aligned) | Hunt (labeled), Investigate (labeled), Connections (count) |
| **IOC Database** (`/iocs`) | Table `<td>` | Horizontal row | Enrich, Copy, Hunt, Investigate, Connections (count) |

### URL Patterns

- **Hunt**: `/search?q={encodeURIComponent(value)}&hunt=1`
  - For intel items: use `item.source_ref || item.cve_ids[0] || item.title`
  - For IOCs: use `ioc.value`
- **Investigate**: `/investigate?id={encodeURIComponent(id)}&type={intel|ioc}&depth=1`
  - For intel items: `id = item.id`, `type = intel`
  - For IOCs: `id = ioc.value`, `type = ioc`

### Sidebar Icon

The **Investigate** page uses the `Telescope` icon in the sidebar for consistency with the Investigate action icon on cards.

### Adding a New Action Icon

1. Choose a lucide-react icon that clearly represents the action.
2. Pick a unique accent color (e.g., `text-emerald-400` / `text-emerald-300` for hover).
3. Use the `icon-btn-3d` class on the button/link. For display-only, use `conn-badge-3d`.
4. Add a `title` attribute with a short description (e.g., `"Hunt — search local + internet"`).
5. Use `e.stopPropagation()` if inside a clickable card.
6. Add the icon to all 3 pages listed above for consistency.
7. Update this file with the new icon entry.

---

## General Rules

- **Do not remove existing UI features** — only add. If something moves, ensure it still exists somewhere accessible.
- **For any major change**, update the relevant docs (`instruction.md`, `README.md`, or `docs/`).
- **Develop locally** at `E:\code\ti-platform`, push to GitHub, deploy to VPS and test online.
- **Deploy flow**: `git push origin main` → SSH to VPS → `git pull` → `docker compose build ui` → `docker compose up -d ui`.
