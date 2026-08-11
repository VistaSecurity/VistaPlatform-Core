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
  Sun, Moon, Play,
} from 'lucide-react';
import { Route, Binary, Ruler, Key, Scale, OctagonAlert, ListChecks, CalendarClock, Gauge, CircleDot, User, Ticket, FolderPlus, ShieldOff, TrendingUp, TrendingDown, Info, SearchX, CheckCheck, Gem, ExternalLink, CircleHelp } from 'lucide-react';

// Explicit, tree-shakeable icon map (kebab-case → component). Add entries as
// sections need them; unknown names render nothing (graceful). This replaces an
// earlier full-`icons`-record import that ballooned the bundle to ~935 kB.
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
};

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
