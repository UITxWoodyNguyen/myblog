/* ============================================================
   WOODIE'S BLOG — Main JavaScript
   Theme Toggle | Search | Tag Filter | Animations
   ============================================================ */

(function () {
  'use strict';

  // ============================================================
  // Theme Toggle
  // ============================================================
  const themeToggle = document.getElementById('theme-toggle');
  
  function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
  }

  if (themeToggle) {
    themeToggle.addEventListener('click', function () {
      const current = document.documentElement.getAttribute('data-theme');
      const next = current === 'dark' ? 'light' : 'dark';
      setTheme(next);
    });
  }

  // ============================================================
  // Mobile Navigation
  // ============================================================
  const hamburger = document.getElementById('nav-hamburger');
  const mobileMenu = document.getElementById('mobile-menu');

  if (hamburger && mobileMenu) {
    hamburger.addEventListener('click', function () {
      hamburger.classList.toggle('active');
      mobileMenu.classList.toggle('open');
    });

    // Close on outside click
    document.addEventListener('click', function (e) {
      if (!hamburger.contains(e.target) && !mobileMenu.contains(e.target)) {
        hamburger.classList.remove('active');
        mobileMenu.classList.remove('open');
      }
    });
  }

  // ============================================================
  // Navbar scroll effect
  // ============================================================
  const navbar = document.getElementById('navbar');
  let lastScrollY = 0;

  if (navbar) {
    window.addEventListener('scroll', function () {
      const scrollY = window.scrollY;
      if (scrollY > 10) {
        navbar.style.boxShadow = '0 1px 8px rgba(0,0,0,0.15)';
      } else {
        navbar.style.boxShadow = 'none';
      }
      lastScrollY = scrollY;
    }, { passive: true });
  }

  // ============================================================
  // Search Functionality
  // ============================================================
  const searchInput = document.getElementById('search-input');
  const postsGrid = document.getElementById('posts-grid');
  const noResults = document.getElementById('no-results');

  if (searchInput && postsGrid) {
    searchInput.addEventListener('input', function () {
      const query = this.value.toLowerCase().trim();
      const cards = postsGrid.querySelectorAll('.post-card');
      let visibleCount = 0;

      cards.forEach(function (card) {
        const title = (card.getAttribute('data-title') || '').toLowerCase();
        const tags = (card.getAttribute('data-tags') || '').toLowerCase();
        const excerpt = (card.getAttribute('data-excerpt') || '').toLowerCase();

        const match = !query || 
          title.includes(query) || 
          tags.includes(query) || 
          excerpt.includes(query);

        card.style.display = match ? '' : 'none';
        if (match) visibleCount++;
      });

      if (noResults) {
        noResults.style.display = visibleCount === 0 ? 'block' : 'none';
      }
    });
  }

  // ============================================================
  // Tag Filter
  // ============================================================
  const tagButtons = document.querySelectorAll('.tag-btn');

  if (tagButtons.length > 0 && postsGrid) {
    tagButtons.forEach(function (btn) {
      btn.addEventListener('click', function () {
        const tag = this.getAttribute('data-tag');

        // Toggle active state
        if (this.classList.contains('active')) {
          this.classList.remove('active');
          filterByTag('');
        } else {
          tagButtons.forEach(function (b) { b.classList.remove('active'); });
          this.classList.add('active');
          filterByTag(tag);
        }
      });
    });
  }

  function filterByTag(tag) {
    if (!postsGrid) return;
    const cards = postsGrid.querySelectorAll('.post-card');
    let visibleCount = 0;

    cards.forEach(function (card) {
      const cardTags = (card.getAttribute('data-tags') || '').toLowerCase();
      const match = !tag || cardTags.includes(tag.toLowerCase());
      card.style.display = match ? '' : 'none';
      if (match) visibleCount++;
    });

    if (noResults) {
      noResults.style.display = visibleCount === 0 ? 'block' : 'none';
    }

    // Clear search when filtering by tag
    if (searchInput) {
      searchInput.value = '';
    }
  }

  // ============================================================
  // Lazy Load Images
  // ============================================================
  function lazyLoadImages() {
    const images = document.querySelectorAll('img[loading="lazy"]');
    
    if ('IntersectionObserver' in window) {
      const observer = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            const img = entry.target;
            if (img.dataset.src) {
              img.src = img.dataset.src;
              img.removeAttribute('data-src');
            }
            img.classList.add('loaded');
            observer.unobserve(img);
          }
        });
      }, { rootMargin: '100px' });

      images.forEach(function (img) {
        observer.observe(img);
      });
    } else {
      // Fallback
      images.forEach(function (img) {
        if (img.dataset.src) {
          img.src = img.dataset.src;
        }
        img.classList.add('loaded');
      });
    }
  }

  // ============================================================
  // Fade-in animation for post content elements
  // ============================================================
  function animatePostContent() {
    const postContent = document.querySelector('.post-content');
    if (!postContent) return;

    const elements = postContent.querySelectorAll('h1, h2, h3, h4, p, ul, ol, pre, blockquote, table, img');
    
    if ('IntersectionObserver' in window) {
      const observer = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          if (entry.isIntersecting) {
            entry.target.style.opacity = '1';
            entry.target.style.transform = 'translateY(0)';
            observer.unobserve(entry.target);
          }
        });
      }, { threshold: 0.1, rootMargin: '0px 0px -30px 0px' });

      elements.forEach(function (el) {
        el.style.opacity = '0';
        el.style.transform = 'translateY(8px)';
        el.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
        observer.observe(el);
      });
    }
  }

  // ============================================================
  // External links open in new tab
  // ============================================================
  function setupExternalLinks() {
    const links = document.querySelectorAll('.post-content a, .page-body a');
    links.forEach(function (link) {
      if (link.hostname !== window.location.hostname) {
        link.setAttribute('target', '_blank');
        link.setAttribute('rel', 'noopener noreferrer');
      }
    });
  }

  // ============================================================
  // Initialize
  // ============================================================
  document.addEventListener('DOMContentLoaded', function () {
    lazyLoadImages();
    animatePostContent();
    setupExternalLinks();
  });

})();
