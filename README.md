# Woodie's Blog

A modern, minimal, dark-themed personal blog built with **Jekyll** and hosted on **GitHub Pages**.

![Dark Theme](https://img.shields.io/badge/theme-dark-0D1117?style=flat-square)
![Jekyll](https://img.shields.io/badge/built_with-Jekyll-CC0000?style=flat-square)
![GitHub Pages](https://img.shields.io/badge/hosted_on-GitHub_Pages-222?style=flat-square)

---

## Features

- Dark theme by default (with light mode toggle)
- Markdown-powered blog posts
- Syntax highlighting (Rouge)
- Search posts by title, tag, or content
- Tag-based filtering
- Responsive design (desktop, tablet, mobile)
- SEO optimized (meta tags, Open Graph, sitemap, RSS feed)
- Smooth animations
- Fast performance
- Zero dependencies (no jQuery, no frameworks)

---

## Project Structure

```
woodie.github.io/
├── _config.yml          # Jekyll configuration
├── _layouts/
│   ├── default.html     # Base layout
│   ├── post.html        # Blog post layout
│   └── page.html        # Static page layout
├── _includes/
│   ├── head.html        # <head> meta, fonts, styles
│   ├── navbar.html      # Navigation bar
│   └── footer.html      # Footer
├── _posts/
│   ├── 2026-01-01-welcome-to-my-blog.md
│   ├── 2026-01-15-getting-started-with-github-pages.md
│   ├── 2026-02-01-modern-css-tips-dark-themes.md
│   └── 2026-02-20-python-for-beginners.md
├── assets/
│   ├── css/
│   │   └── style.css    # All styles
│   ├── js/
│   │   └── main.js      # Theme toggle, search, tags
│   └── images/          # Blog images
├── index.html           # Home page (post list)
├── about.md             # About page
├── 404.html             # 404 error page
├── Gemfile              # Ruby dependencies
└── README.md            # This file
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

1. Create a new file in `_posts/` with the format:
   ```
   YYYY-MM-DD-your-post-title.md
   ```

2. Add frontmatter at the top:
   ```markdown
   ---
   title: "Your Post Title"
   date: 2026-03-01
   tags: [tag1, tag2]
   description: "A brief description of your post."
   ---

   Your content here in Markdown...
   ```

3. Supported Markdown features:
   - Headings (`# H1` through `###### H6`)
   - **Bold**, *italic*, ~~strikethrough~~
   - Code blocks with syntax highlighting
   - Images: `![alt](url)`
   - Links: `[text](url)`
   - Tables
   - Blockquotes
   - Ordered and unordered lists

4. Commit and push — GitHub Pages will automatically rebuild.

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