# Wood13nqxy3n's Blog

A modern, minimal, dark-themed personal CTF blog built with **Jekyll** and hosted on **GitHub Pages**.

![Dark Theme](https://img.shields.io/badge/theme-dark-0D1117?style=flat-square)
![Jekyll](https://img.shields.io/badge/built_with-Jekyll-CC0000?style=flat-square)
![GitHub Pages](https://img.shields.io/badge/hosted_on-GitHub_Pages-222?style=flat-square)

---

## Features

- Dark theme by default (with light mode toggle)
- Markdown-powered blog posts
- Syntax highlighting (Rouge) with copy button
- Search posts by title, tag, or content
- **Category system** (CTF → Tournament / Training)
- Tag-based filtering
- Category + tag + search combined filtering
- Table of Contents sidebar on posts (HackMD-style)
- Pagination (10 posts per page)
- Responsive design (desktop, tablet, mobile)
- SEO optimized (meta tags, Open Graph, sitemap, RSS feed)
- Smooth animations
- Fast performance
- Zero dependencies (no jQuery, no frameworks)

---

## Project Structure

```
myblog/
├── _config.yml              # Jekyll configuration
├── _layouts/
│   ├── default.html         # Base layout
│   ├── post.html            # Blog post layout (with TOC)
│   ├── page.html            # Static page layout
│   └── category.html        # Category listing layout
├── _includes/
│   ├── head.html            # <head> meta, fonts, styles
│   ├── navbar.html          # Navigation bar
│   └── footer.html          # Footer
├── _posts/
│   ├── ctf/
│   │   ├── tournament/
│   │   │   ├── PascalCTF/   # Posts for PascalCTF contest
│   │   │   ├── BITSCTF/     # Posts for BITSCTF contest
│   │   │   ├── 0xFUN/       # Posts for 0xFUN contest
│   │   │   └── UVT/         # Posts for UVT contest
│   │   └── training/
│   │       ├── picoCTF/     # picoCTF practice writeups
│   │       └── Dreamhack/   # Dreamhack practice writeups
│   └── research/
│       └── math/            # Research write-ups and notes
├── categories/
│   ├── index.html           # /categories/ overview page
│   ├── tournament.html      # /categories/tournament/ listing
│   ├── research.html        # /categories/research/ listing
│   └── training.html        # /categories/training/ listing
├── assets/
│   ├── css/
│   │   └── style.css        # All styles
│   └── js/
│       └── main.js          # Theme toggle, search, filters
├── index.html               # Home page (post list + filters)
├── about.md                 # About page
├── 404.html                 # 404 error page
├── Gemfile                  # Ruby dependencies
└── README.md                # This file
```

---

## Deploy to GitHub Pages (Step by Step)

### Option A: User/Organization Site (recommended)

1. **Create a repository** named `<username>.github.io` on GitHub

2. **Clone** this repository:
   ```bash
   git clone https://github.com/<username>/<username>.github.io.git
   cd <username>.github.io
   ```

3. **Copy all files** from this project into the cloned repo

4. **Edit `_config.yml`**:
   ```yaml
   title: Your Blog Name
   description: "Your blog description"
   author: Your Name
   url: "https://<username>.github.io"
   baseurl: ""
   github_username: <your-github-username>
   ```

5. **Push to GitHub**:
   ```bash
   git add .
   git commit -m "Initial blog setup"
   git push origin main
   ```

6. **Enable GitHub Pages** (if not auto-enabled):
   - Go to repository **Settings** → **Pages**
   - Source: **Deploy from a branch**
   - Branch: **main** / **(root)**
   - Click **Save**

7. **Visit** `https://<username>.github.io` — your blog is live!

### Option B: Project Site

1. Create a repository with any name (e.g., `my-blog`)

2. Update `_config.yml`:
   ```yaml
   baseurl: "/my-blog"
   ```

3. Push to GitHub and enable Pages from Settings → Pages

4. Visit `https://<username>.github.io/my-blog`

---

## Writing a New Post

1. Create a new `.md` file in the appropriate category folder:
   ```
   _posts/ctf/tournament/<ContestName>/YYYY-MM-DD-challenge-name.md
   _posts/ctf/training/<Platform>/YYYY-MM-DD-challenge-name.md
   ```

   For example:
   ```
   _posts/ctf/tournament/BITSCTF/2026-03-04-new-challenge.md
   _posts/ctf/training/Dreamhack/2026-03-04-some-exercise.md
   ```

2. Add frontmatter at the top:
   ```markdown
   ---
   title: "Your Post Title"
   date: 2026-03-01
   categories: [CTF, Tournament]
   tags: [ContestName, pwn]
   description: "A brief description of your post."
   ---

   Your content here in Markdown...
   ```

   - Use `categories: [CTF, Tournament]` for contest writeups
   - Use `categories: [CTF, Training]` for practice/training writeups

3. Supported Markdown features:
   - Headings (`# H1` through `###### H6`)
   - **Bold**, *italic*, ~~strikethrough~~
   - Code blocks with syntax highlighting (+ copy button)
   - Images: `![alt](url)`
   - Links: `[text](url)`
   - Tables
   - Blockquotes
   - Ordered and unordered lists

4. Commit and push — GitHub Pages will automatically rebuild.

---

## Category System

The blog uses a **2-level hierarchy**: **Category → Sub-category**.

```
_posts/
  <category>/
    <sub-category>/
      <group>/
        YYYY-MM-DD-post-name.md
```

Currently:

```
_posts/
  ctf/                         ← Category: CTF
    tournament/                ← Sub-category: Tournament
      PascalCTF/               ← Contest group
      BITSCTF/
      0xFUN/
      UVT/
    training/                  ← Sub-category: Training
      picoCTF/                 ← Platform group
      Dreamhack/
```

The `categories` field in frontmatter maps to this: `categories: [<Category>, <Sub-category>]`

---

### Adding a Post to an Existing Sub-category

Just create a folder for the contest/platform (if it doesn't exist) and add your `.md`:

```bash
mkdir -p _posts/ctf/tournament/NewContest
```

```yaml
# _posts/ctf/tournament/NewContest/2026-03-04-challenge.md
---
title: "Challenge - NewContest Write Up"
date: 2026-03-04
categories: [CTF, Tournament]
tags: [NewContest, pwn]
description: "Writeup description"
---
```

No other config changes needed. Jekyll auto-discovers posts in subfolders.

---

### Adding a New Research Topic

Example: add a **Math** research topic.

**Step 1** — Create the folder:

```bash
mkdir -p _posts/research/math
```

**Step 2** — Add posts with the new topic in frontmatter:

```yaml
# _posts/research/math/2026-03-04-article.md
---
title: "Math Research Article"
date: 2026-03-04
categories: [Research, Math]
tags: [math, analysis]
description: "Description"
---
```

**Step 3** — Create the category page at `categories/research.html`:

```yaml
---
layout: category
title: Research
category: Research
permalink: /categories/research/
---
```

**Step 4** — Add the Research card to `categories/index.html` as a top-level folder, not under CTF.

**Step 5** — (Optional) Add the Research option to `index.html`:

```html
<option value="Research">Research</option>
```

---

### Adding a Brand New Category

Example: add a completely new top-level category **Blog** (separate from CTF).

**Step 1** — Create the folder structure:

```bash
mkdir -p _posts/blog/tech
mkdir -p _posts/blog/personal
```

**Step 2** — Add posts with the new category:

```yaml
# _posts/blog/tech/2026-03-04-my-article.md
---
title: "My Article"
date: 2026-03-04
categories: [Blog, Tech]
tags: [linux, tools]
description: "Description"
---
```

**Step 3** — Create sub-category pages:

```yaml
# categories/tech.html
---
layout: category
title: Tech
category: Tech
permalink: /categories/tech/
---
```

```yaml
# categories/personal.html
---
layout: category
title: Personal
category: Personal
permalink: /categories/personal/
---
```

**Step 4** — Add a new `.category-group` block in `categories/index.html` (copy the CTF block and change names/icons).

**Step 5** — Add filter buttons to `index.html`:

```html
<button class="cat-btn" data-category="Tech">Tech</button>
<button class="cat-btn" data-category="Personal">Personal</button>
```

---

### Quick Reference

| I want to...                         | What to do                                                        |
|--------------------------------------|-------------------------------------------------------------------|
| Add a post to existing sub-category  | Create `.md` in the right folder, set `categories` in frontmatter |
| Add a new contest/platform group     | `mkdir _posts/ctf/tournament/NewName` + add `.md` files           |
| Add a new sub-category under CTF     | Folder + category page + update `categories/index.html`           |
| Add a brand new top-level category   | Folder + sub-cat pages + new group in `categories/index.html`     |

---

## Adding Images

Place images in `assets/images/` and reference them in posts:

```markdown
![My Image](/assets/images/my-image.png)
```

---

## Local Development (Optional)

If you want to preview locally before pushing:

```bash
# Install Ruby and Bundler (if not installed)
# See: https://jekyllrb.com/docs/installation/

# Install dependencies
bundle install

# Run local server
bundle exec jekyll serve

# Open http://localhost:4000
```

---

## Customization

### Change Colors

Edit CSS custom properties in `assets/css/style.css`:

```css
:root {
  --bg: #0D1117;
  --surface: #161B22;
  --primary: #58A6FF;
  --text: #C9D1D9;
  /* ... */
}
```

### Change Fonts

Update the Google Fonts import in `_includes/head.html`.

### Add New Pages

Create a new `.md` file in the root with frontmatter:

```markdown
---
layout: page
title: Contact
permalink: /contact/
---

Your content...
```

Then add a link in `_includes/navbar.html`.

---

## License

MIT License. Feel free to use and modify.