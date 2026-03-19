## Fonts
- **Primary:** Google Sans
```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Google+Sans:ital,opsz,wght@0,17..18,400..700;1,17..18,400..700&display=swap" rel="stylesheet">
```

## Typography Scale
| Style       | Size  | Weight | Line Height | Use                  |
|-------------|-------|--------|-------------|----------------------|
| Headline 1  | 32px  | 700    | 1.25×       | Page titles          |
| Headline 2  | 24px  | 600    | 1.3×        | Section headings     |
| Headline 3  | 20px  | 600    | 1.4×        | Sub-headings         |
| Body        | 16px  | 400    | 1.5×        | Core text            |
| Small       | 14px  | 400    | 1.5×        | Labels, metadata     |

## Color Palette

### Role Assignment (60-30-10)
- **60% Neutral:** `#ffffff` (white) + `#f1f2f6` (light gray) — backgrounds, surfaces
- **30% Secondary:** `#2f3542` (dark charcoal) — sidebar, text, headers
- **10% Accent/CTA:** `#2ed573` (green) — primary actions, active states, success

### Semantic Colors
- **Warning:** `#eccc68` (yellow)
- **Error/Destructive:** `#ff4757` (red)
- **Info:** `#3742fa` (blue)

## Border Radius
| Element              | Radius |
|----------------------|--------|
| Buttons              | 16px   |
| Cards/Panels         | 16px   |
| Inputs/Fields        | 16px   |

> Unified 16px radius across all interactive elements for a cohesive, rounded look.

## Vibes
- Welcoming
- Energetic
- Playful, Fun
- Fast/Snappy
- High tech
- Clean, minimal and uncluttered

## Look and Feel
- Playful, smooth and snappy animations (150-400ms, cubic-bezier(0.4, 0, 0.2, 1))
- Respects prefers-reduced-motion

## Shadows
- Subtle, 2-8px blur, low opacity
- Used to indicate interactive layers and depth

## Density
- Comfortable — balanced breathing room with good content visibility

## Layout
- Collapsible sidebar (both mobile and desktop)
- Sidebar: default **open** on desktop, **closed** on mobile (hamburger icon)
- Mobile-first breakpoints: default (mobile) -> 768px (tablet) -> 1024px (desktop)
