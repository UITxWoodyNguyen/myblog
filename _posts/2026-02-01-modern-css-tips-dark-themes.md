---
title: "Modern CSS Tips for Dark Themes"
date: 2026-02-01
tags: [css, design, frontend]
description: "Essential CSS techniques for building beautiful dark theme interfaces that users love."
---

Dark themes are everywhere now — from VS Code to GitHub to Twitter. Let me share some CSS techniques I've learned for building great dark UIs.

## CSS Custom Properties

The foundation of any good theme system is CSS custom properties:

```css
:root {
  --bg: #0D1117;
  --surface: #161B22;
  --text: #C9D1D9;
  --primary: #58A6FF;
  --border: #30363D;
}

[data-theme="light"] {
  --bg: #FFFFFF;
  --surface: #F6F8FA;
  --text: #1F2328;
  --primary: #0969DA;
  --border: #D0D7DE;
}
```

This approach lets you swap themes by changing a single attribute on `<html>`.

## Preventing Flash of Unstyled Content

A common problem with theme toggles is FOUC. Here's how to prevent it:

```html
<script>
  // Run BEFORE page renders
  const theme = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', theme);
</script>
```

> Place this script in `<head>` **before** your CSS to ensure no flash.

## Color Contrast

Always check contrast ratios. Here's a quick reference:

| Text Type | Min Ratio | Example |
|-----------|-----------|---------|
| Body text | 4.5:1 | `#C9D1D9` on `#0D1117` |
| Large text | 3:1 | Headings |
| UI elements | 3:1 | Borders, icons |

## Subtle Borders

Don't use solid black or white borders. Use semi-transparent colors:

```css
.card {
  /* ❌ Too harsh */
  border: 1px solid #000;

  /* ✅ Subtle and adaptive */
  border: 1px solid var(--border);
}
```

## Backdrop Blur for Glassmorphism

A modern technique for navbars and overlays:

```css
.navbar {
  background: rgba(13, 17, 23, 0.8);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
}
```

## Smooth Transitions

Always transition theme changes:

```css
body {
  transition: background-color 0.2s ease, color 0.2s ease;
}
```

But be careful — **don't transition everything**. Only transition properties that change:

```css
/* ❌ Performance killer */
* { transition: all 0.3s; }

/* ✅ Specific and performant */
body {
  transition: background-color 0.2s ease, color 0.2s ease;
}
```

## Syntax Highlighting

For code blocks in dark themes, I recommend these color families:

- **Keywords**: Red/Orange (`#ff7b72`)
- **Strings**: Blue (`#a5d6ff`)
- **Functions**: Purple (`#d2a8ff`)
- **Comments**: Gray (`#8b949e`)
- **Variables**: Cyan (`#79c0ff`)

These colors work well against dark backgrounds and provide excellent readability.

## Final Thoughts

Dark themes are more than just inverting colors. Pay attention to:

1. **Contrast ratios** — Accessibility matters
2. **Elevation** — Use lighter surfaces for elevated elements
3. **Saturated colors** — Reduce saturation for dark backgrounds
4. **Shadows** — They work differently on dark backgrounds

---

*What's your favorite dark theme? Let me know!* 🌙
