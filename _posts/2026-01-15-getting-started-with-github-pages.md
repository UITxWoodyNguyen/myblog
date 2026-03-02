---
title: "Getting Started with GitHub Pages"
date: 2026-01-15
tags: [github, tutorial, devops]
description: "A complete guide to setting up your own website with GitHub Pages — from zero to deployed."
---

GitHub Pages is one of the easiest ways to host a static website for free. In this guide, I'll walk you through setting up your own site from scratch.

## What is GitHub Pages?

GitHub Pages is a static site hosting service that takes HTML, CSS, and JavaScript files directly from a repository on GitHub and publishes a website.

### Key Features

| Feature | Details |
|---------|---------|
| **Cost** | Free |
| **Custom Domain** | Supported |
| **HTTPS** | Automatic |
| **Build Tool** | Jekyll (built-in) |
| **Bandwidth** | 100GB/month |

## Step 1: Create a Repository

Create a new repository named `username.github.io`, where `username` is your GitHub username.

```bash
# Clone the repository
git clone https://github.com/username/username.github.io.git

# Navigate into the directory
cd username.github.io
```

## Step 2: Add Your Content

Create an `index.html` file:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>My Website</title>
</head>
<body>
  <h1>Hello, GitHub Pages!</h1>
</body>
</html>
```

## Step 3: Push and Deploy

```bash
git add .
git commit -m "Initial commit"
git push origin main
```

That's it! Your site will be live at `https://username.github.io` within a few minutes.

## Using Jekyll

GitHub Pages has built-in support for Jekyll. Simply add a `_config.yml` file:

```yaml
title: My Blog
description: A personal blog
markdown: kramdown
plugins:
  - jekyll-seo-tag
  - jekyll-sitemap
```

> **Pro tip:** Jekyll processes Markdown files automatically, so you can write your content in `.md` files instead of HTML.

## Custom Domain

To use a custom domain:

1. Add a `CNAME` file to your repo with your domain name
2. Configure DNS with your registrar
3. Enable HTTPS in repository settings

```
# CNAME file content
yourdomain.com
```

## Conclusion

GitHub Pages is a powerful, free hosting solution. Whether you're building a portfolio, blog, or project documentation, it's hard to beat the simplicity.

---

*Happy deploying!* 🚀
