# ADR 015: The site moves to chrome, motion and a floating navigation

Status: Accepted (2026-10-13). Supersedes the motion and surface rules in `docs/07-ux/DESIGN-SYSTEM.md` and the "no tilt or perspective" line in `docs/07-ux/PAGE-SPECS.md`.

Context: the owner asked for the whole site — marketing, dashboard and docs — to take the feel of a specific reference (large light-weight type on black, inertial scrolling, a moving 3D logo in the hero, a frosted pill navigation, rounded cards that each carry a small live interface), while keeping Myrqen's own identity. The existing design system forbade almost every one of those devices: no tilt, perspective or rotation; no glassmorphism; no glow; inertial scrolling and animation libraries were rejected. Those were taste rules, not product rules, and the owner overruled them explicitly.

Decision:

- Inertial scrolling with Lenis on marketing routes only, mounted by the marketing header; off under `prefers-reduced-motion`, native on touch (`syncTouch: false`), and never in the signed-in app.
- The hero centrepiece is the Myrqen mark extruded in three.js and lit by strip lights baked into an environment map. Raw three, no react-three-fiber. It is fetched after idle, only with WebGL, renders over a static SVG version of the mark, pauses off-screen and in hidden tabs, drops to a low tier on phones and low-core machines, and falls back to the static mark on a lost context. Reduced motion keeps the object and reduces the motion to a slow small sway without pointer tracking.
- The marketing header is a floating pill that frosts once the page scrolls. Cards use large radii (26px), a raised-to-base vertical gradient and a 1px hairline. Chrome (a five-stop grey gradient) is the only decorative material, used for the featured plan's edge and badge.
- Colour: black, four steps of white ink, chrome. Green `#4ade5a` keeps one meaning — verified / passed — everywhere, including the local report and the docs, which had drifted to lime `#B9F34A`.
- Type: Inter at weight 400 for display sizes with tight tracking; mono only for labels, data and code.
- Motion is CSS wherever it can be: the hero rises on load from a visible state (so the headline still counts as LCP), sections reveal once on scroll, and card mini-interfaces play their sequence once when revealed.

Unchanged and still binding (from `PRODUCT.md`): source-available wording, the measured figures shown unhedged with the unflattering one first, "a clean report is not evidence…", the cell alphabet and the mascot as identity, WCAG 2.2 AA, reduced motion removing movement and never information, and inventing no numbers, customers or claims. Copy that states a count of the figures is now computed from them rather than written.

Consequences: the home page ships ~150 KB gzip of three.js, loaded lazily after idle and never on the critical path. Lenis adds ~4 KB. Any new marketing page gets smooth scrolling by using `SiteHeader`. The older component CSS in `globals.css` that the redesign replaces is dead until the cleanup pass removes it; new site-level rules live in `app/site.css`, home rules in `app/home.css`, both imported after `globals.css`.
