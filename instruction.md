# IntelWatch — Development Instructions

## Action Icons

Every intel item, IOC, or entity card/row should include the standard action icons described below. 
Follow this guide when adding new pages or features that display intel or IOC data.

### Standard Icon Set

| Icon | Lucide Name | Purpose | Clickable | Navigates To |
|------|-------------|---------|-----------|--------------|
| **Hunt** | `Crosshair` | Search local database + live internet lookup | Yes | `/search?q=<value>&hunt=1` |
| **Investigate** | `Telescope` | Open relationship graph (1-hop focused view) | Yes | `/investigate?id=<id>&type=<intel\|ioc>&depth=1` |
| **Connections** | `Share2` | Show count of related entities (IOCs or intel items) | No | — (display only) |
| **Enrich** | `Zap` | Enrich IOC via VirusTotal / Shodan | Yes | Triggers API call |
| **Copy** | `Copy` / `Check` | Copy value to clipboard | Yes | — (in-place action) |

### Design Rules

1. **Keep it basic** — No colored backgrounds, no borders on icon buttons. Just the icon.
2. **Default color** — Icons use `text-muted-foreground` at rest.
3. **Hover color** — Each icon gets its own accent color on hover only:
   - Hunt → `hover:text-blue-400`
   - Investigate → `hover:text-purple-400`
   - Enrich → `hover:text-yellow-400`
   - Copy → `hover:text-foreground`
   - Connections (static) → `text-muted-foreground/60` (no hover, not clickable)
4. **Hover background** — Use `hover:bg-muted/60` (subtle grey). No colored backgrounds.
5. **Padding** — `p-1.5 rounded` for icon-only buttons; `px-1.5 py-0.5 rounded` for labeled links.
6. **Size** — Icons are `h-3.5 w-3.5` in table rows, `h-3 w-3` in card meta rows.
7. **Labels** — On cards (IntelCard), Hunt and Investigate show a `text-[10px]` label next to the icon. On table rows (IOC Database) and stacked layouts (Threats), icons are icon-only.
8. **Connections badge** — Always shows `<Share2 icon> <count>` as plain text, never clickable.

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
2. Use `text-muted-foreground` as default color, pick a unique accent for hover.
3. Add a `title` attribute with a short description (e.g., `"Hunt — search local + internet"`).
4. If the icon navigates, use `<button>` with `router.push()` or `<Link>`. Use `e.stopPropagation()` if inside a clickable card.
5. If the icon is display-only (like Connections), use `<span>` instead of `<button>`.
6. Add the icon to all 3 pages listed above for consistency.
7. Update this file with the new icon entry.

---

## General Rules

- **Do not remove existing UI features** — only add. If something moves, ensure it still exists somewhere accessible.
- **For any major change**, update the relevant docs (`instruction.md`, `README.md`, or `docs/`).
- **Develop locally** at `E:\code\ti-platform`, push to GitHub, deploy to VPS and test online.
- **Deploy flow**: `git push origin main` → SSH to VPS → `git pull` → `docker compose build ui` → `docker compose up -d ui`.
