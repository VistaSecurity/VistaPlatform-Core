import type { LucideIcon, LucideProps } from 'lucide-react';
import {
  Server, FileBadge, SlidersHorizontal, Network, Link, Clock, Search,
  ChevronLeft, ChevronRight, ChevronDown, ChevronUp, AlertTriangle, Loader,
  Inbox, Layers, Radar, Database, ShieldCheck, Wrench, LayoutDashboard,
  Shield, Bell, Settings, Check, X, Plus, Minus, ArrowUpRight, ArrowRight,
  Download, Upload, Filter, Terminal, Lock, KeyRound, FileText, Activity,
  Cloud, CircleAlert, Wifi, MoreVertical, ShieldX, XCircle, Mail, Eye, EyeOff, BadgeCheck, LogOut, Server as Host,
  Building2, Palette, CreditCard, ChartColumn, Users, ShieldHalf, Fingerprint,
  Plug, BellRing, ScrollText, Recycle, Archive, Crop, History,
  MapPin, ArrowLeft, UserRound, MonitorSmartphone, Link2, Accessibility,
  ShieldAlert, DraftingCompass, ImagePlus, Smartphone, UploadCloud, FileUp, UserPlus,
  Sun, Moon, Play, RefreshCw, Vault, Sparkles, PlugZap, Unplug,
  Waypoints, CircuitBoard, AppWindow, Workflow, Maximize, Minimize, Crosshair,
  Zap, ArrowLeftRight, Package, Cpu,
  FilterX, GitMerge, GitCompare, Split, Equal, CircleCheck, CircleUser, EthernetPort,
  ListFilter, SearchCode, Trash2, Bookmark, Bot, FileCheck, Send, UserX, Power,
  ChartNoAxesColumn, MapIcon, ArrowUp, ArrowDown, MailCheck, CircleSlash, Copy,
  Tag, FolderTree, Box, Type, ScanBarcode, List, Tags,
  Blocks, Boxes, Briefcase, Cctv, CloudCog, CloudLightning, Cog, Computer, Container,
  Factory, Globe, HardDrive, Laptop, Monitor, Printer, Radio, RadioTower, Router,
  ServerCog, Share2, SquareStack, Webhook,
} from 'lucide-react';
import { Route, Binary, Ruler, Key, Scale, OctagonAlert, ListChecks, CalendarClock, Gauge, CircleDot, User, Ticket, FolderPlus, ShieldOff, TrendingUp, TrendingDown, Info, SearchX, CheckCheck, Gem, ExternalLink, CircleHelp, CircleDashed, Shapes } from 'lucide-react';

// Explicit, tree-shakeable icon map (kebab-case → component). Add entries as
// sections need them; an unknown name renders a question-mark placeholder (see
// `Icon` below), and icon-names.test.ts fails on any name the UI uses that is
// missing here. This replaces an earlier full-`icons`-record import that
// ballooned the bundle to ~935 kB.
const MAP: Record<string, LucideIcon> = {
  server: Server, host: Host, 'file-badge': FileBadge, 'sliders-horizontal': SlidersHorizontal,
  network: Network, link: Link, 'clock-alert': Clock, clock: Clock, search: Search,
  'chevron-left': ChevronLeft, 'chevron-right': ChevronRight, 'chevron-down': ChevronDown, 'chevron-up': ChevronUp,
  'alert-triangle': AlertTriangle, loader: Loader, inbox: Inbox, layers: Layers, radar: Radar,
  database: Database, 'shield-check': ShieldCheck, wrench: Wrench, 'layout-dashboard': LayoutDashboard,
  shield: Shield, bell: Bell, settings: Settings, check: Check, x: X, plus: Plus, minus: Minus,
  'arrow-up-right': ArrowUpRight, 'arrow-right': ArrowRight, download: Download, upload: Upload,
  filter: Filter, terminal: Terminal, lock: Lock, 'key-round': KeyRound, 'file-text': FileText,
  activity: Activity, cloud: Cloud, 'circle-alert': CircleAlert, wifi: Wifi, 'more-vertical': MoreVertical,
  'shield-x': ShieldX, 'x-circle': XCircle, mail: Mail, eye: Eye, 'eye-off': EyeOff, 'badge-check': BadgeCheck, 'log-out': LogOut,
  route: Route, binary: Binary, ruler: Ruler, key: Key, scale: Scale, 'octagon-alert': OctagonAlert,
  'list-checks': ListChecks, 'calendar-clock': CalendarClock, gauge: Gauge, 'circle-dot': CircleDot,
  user: User, ticket: Ticket, 'folder-plus': FolderPlus, 'shield-off': ShieldOff,
  'trending-up': TrendingUp, 'trending-down': TrendingDown, info: Info, 'search-x': SearchX, 'check-check': CheckCheck,
  'building-2': Building2, palette: Palette, 'credit-card': CreditCard, 'chart-column': ChartColumn,
  users: Users, 'shield-half': ShieldHalf, fingerprint: Fingerprint, plug: Plug,
  'bell-ring': BellRing, 'scroll-text': ScrollText, recycle: Recycle, archive: Archive,
  crop: Crop, history: History, 'map-pin': MapPin, 'arrow-left': ArrowLeft,
  'user-round': UserRound, 'monitor-smartphone': MonitorSmartphone, 'link-2': Link2,
  accessibility: Accessibility, 'shield-alert': ShieldAlert, 'drafting-compass': DraftingCompass,
  'image-plus': ImagePlus, smartphone: Smartphone, 'upload-cloud': UploadCloud, 'file-up': FileUp, 'user-plus': UserPlus,
  gem: Gem, 'external-link': ExternalLink, sun: Sun, moon: Moon, play: Play,
  // Manual re-evaluation (Risk & Compliance → Posture).
  refresh: RefreshCw,
  // Data Protection lens (Inventory) — at-rest, keyed-and-durable protection.
  vault: Vault,
  // "we can't answer that" / "offered but not observed" — the honest-absence
  // pair used by the crypto-configuration drawer's risk explanation.
  'circle-help': CircleHelp, 'circle-dashed': CircleDashed,
  // "a model wrote this sentence" — the CBOM comparison's narrative label.
  // Distinct from `scale` (the rule-written one) on purpose: which of the two
  // produced the text is the thing the badge exists to say.
  sparkles: Sparkles,
  // Settings → AI assistant: whether a model provider is configured for this
  // deployment. Two glyphs rather than one tinted one, because "connected" and
  // "nothing configured" are the whole answer that card gives.
  'plug-zap': PlugZap, unplug: Unplug,
  // The asset map (Inventory → Map, ADR-0006 D4). `waypoints` is the lens's own
  // nav icon and was already named by the lens registry and the relationship
  // proposal row while missing here, so both rendered the unknown-name
  // placeholder; the rest are the map's class-group glyphs (matching what the
  // class picker shows for the same taxonomy root) and its chrome.
  waypoints: Waypoints, 'circuit-board': CircuitBoard, 'app-window': AppWindow,
  workflow: Workflow, maximize: Maximize, minimize: Minimize, crosshair: Crosshair,
  // Blast radius + direction swap — named by the Relationships tab's impact
  // panel before this, and by the map's impact overlay now.
  zap: Zap, 'arrow-left-right': ArrowLeftRight,
  // The Software lens's own nav glyph, missing since 2.6b and surfaced by the
  // lens-icon guard in map-reachability.test.ts. It is the map lens's immediate
  // neighbour in the Assets group, so a guard that let it keep rendering a
  // question mark would not be worth having. `package` also serves the software
  // BOM kind's badge.
  package: Package,
  // The hardware BOM kind's badge (Risk & Compliance → Bills of Materials).
  cpu: Cpu,
  // The command palette's asset-CLASS result kind (ADR-0006 D9). A taxonomy of
  // shapes is what a class is, and it has to differ from every class's own
  // glyph — the row says "this is a class", not "this is a server".
  shapes: Shapes,
  // Second spellings of glyphs already imported above. lucide renamed
  // help-circle → circle-help and alert-triangle → triangle-alert between
  // majors, and `refresh` is this map's own short name for refresh-cw; call
  // sites use both spellings of each, and the component is the same one, so
  // they share an import rather than each getting its own.
  'help-circle': CircleHelp, 'triangle-alert': AlertTriangle, 'refresh-cw': RefreshCw,
  // bar-chart-2 became chart-no-axes-column — NOT chart-column, which was
  // bar-chart-3 and draws axes. Settings → Policies' "View posture" button
  // named the axis-less bars, so that is the glyph it gets.
  'bar-chart-2': ChartNoAxesColumn,
  // Discovery: the approvals page's cleared-filter state, the merge-proposal
  // row's merge / keep-separate / equal-field marks (merge also on the
  // auto-merged section and the asset page), and the SBOM page's verdicts.
  'filter-x': FilterX, 'git-merge': GitMerge, split: Split, equal: Equal, 'circle-check': CircleCheck,
  // Inventory: the asset page's Overview and Endpoints tabs, the facet rail,
  // the query editor, saved views (bookmark, delete — delete also on the
  // Relationships tab), and the map's Topology view.
  'circle-user': CircleUser, 'ethernet-port': EthernetPort, 'list-filter': ListFilter,
  'search-code': SearchCode, bookmark: Bookmark, 'trash-2': Trash2, map: MapIcon,
  // Settings: API tokens, account, integrations, people, policies.
  bot: Bot, 'file-check': FileCheck, 'git-compare': GitCompare, send: Send, 'user-x': UserX, power: Power,
  // Named only inside `name={cond ? 'a' : 'b'}` expressions, which is how they
  // hid from a scan of string-literal props: the merge explanation's for /
  // against arrows, the invite page's accepted state, the facet rail's
  // "no findings" state, and the copy-to-clipboard buttons' resting glyph.
  'arrow-up': ArrowUp, 'arrow-down': ArrowDown, 'mail-check': MailCheck, 'circle-slash': CircleSlash, copy: Copy,
  // The query editor's completion kinds (field / namespace / class / keyword),
  // named in a lookup table keyed by kind rather than in an `icon:` field.
  tag: Tag, 'folder-tree': FolderTree, box: Box, type: Type,
  // Passed as `icon="..."` to SectionLabel on the asset page (Identifiers,
  // class attributes, Tags) — an attribute, not a `name=` prop, so a scan of
  // `<Icon name=` literals never saw them either.
  'scan-barcode': ScanBarcode, list: List, tags: Tags,
  // The asset-class taxonomy (standards/asset-classes.yaml) names each class's
  // icon as a lucide EXPORT name — `ServerCog` — because the generator checks
  // it against the package. `classIcon()` folds that onto these kebab keys, so
  // every icon the taxonomy names has to be drawable here: these are the ones
  // no other caller had already needed. (icon-names.test.ts walks the whole
  // taxonomy.) `circle-question-mark` is lucide's current name for CircleHelp.
  blocks: Blocks, boxes: Boxes, briefcase: Briefcase, cctv: Cctv, 'cloud-cog': CloudCog,
  'cloud-lightning': CloudLightning, cog: Cog, computer: Computer, container: Container,
  factory: Factory, globe: Globe, 'hard-drive': HardDrive, laptop: Laptop, monitor: Monitor,
  printer: Printer, radio: Radio, 'radio-tower': RadioTower, router: Router, 'server-cog': ServerCog,
  'share-2': Share2, 'square-stack': SquareStack, webhook: Webhook, 'circle-question-mark': CircleHelp,
};

/** Every name `Icon` can actually draw.
 *
 *  Exported so a registry that names icons as bare strings — the inventory lens
 *  list, the asset tabs, the settings nav — can be checked against it in a test
 *  rather than discovered as a question mark in the UI. The failure is silent
 *  by design in production (a placeholder beats an invisible control), which is
 *  exactly why it needs an assertion somewhere. */
export const ICON_NAMES: readonly string[] = Object.keys(MAP);

export function Icon({ name, size = 16, ...rest }: { name: string; size?: number } & LucideProps) {
  const Cmp = MAP[name];
  if (Cmp) return <Cmp size={size} {...rest} />;
  // Unknown icon name: in dev, warn and render a visible placeholder so the
  // missing glyph surfaces immediately instead of becoming an invisible-but-
  // clickable control (see the `play` ghost-button bug). In prod, render a
  // neutral placeholder rather than nothing so the control still has an affordance.
  if (import.meta.env.DEV) {
    console.warn(`[Icon] unknown icon name "${name}" — add it to the MAP in components/ui/icon.tsx`);
  }
  return <CircleHelp size={size} {...rest} />;
}
