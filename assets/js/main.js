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
  var activeCategory = 'all';
  var activeTag = '';
  var currentPage = 1;
  var postsPerPage = 10;

  // Get all post cards once
  var allCards = postsGrid ? Array.from(postsGrid.querySelectorAll('.post-card')) : [];

  // Pagination elements
  var paginationNav = document.getElementById('pagination');
  var pagePrev = document.getElementById('page-prev');
  var pageNext = document.getElementById('page-next');
  var pageInfo = document.getElementById('page-info');

  function getFilteredCards() {
    var query = searchInput ? searchInput.value.toLowerCase().trim() : '';
    return allCards.filter(function (card) {
      var title = (card.getAttribute('data-title') || '').toLowerCase();
      var tags = (card.getAttribute('data-tags') || '').toLowerCase();
      var excerpt = (card.getAttribute('data-excerpt') || '').toLowerCase();
      var category = (card.getAttribute('data-category') || '').toLowerCase();

      var matchSearch = !query || title.includes(query) || tags.includes(query) || excerpt.includes(query);
      var matchCategory = activeCategory === 'all' || category.includes(activeCategory.toLowerCase());
      var matchTag = !activeTag || tags.includes(activeTag.toLowerCase());

      return matchSearch && matchCategory && matchTag;
    });
  }

  function renderPage() {
    if (!postsGrid) return;
    var filtered = getFilteredCards();
    var totalPages = Math.max(1, Math.ceil(filtered.length / postsPerPage));

    // Clamp current page
    if (currentPage > totalPages) currentPage = totalPages;
    if (currentPage < 1) currentPage = 1;

    var start = (currentPage - 1) * postsPerPage;
    var end = start + postsPerPage;
    var pageCards = filtered.slice(start, end);

    // Hide all, show only current page's filtered cards
    allCards.forEach(function (card) { card.style.display = 'none'; });
    pageCards.forEach(function (card, i) {
      card.style.display = '';
      card.style.animationDelay = (i * 0.05) + 's';
    });

    // No results message
    if (noResults) {
      noResults.style.display = filtered.length === 0 ? 'block' : 'none';
    }

    // Update pagination UI
    if (paginationNav) {
      paginationNav.style.display = totalPages > 1 ? '' : 'none';
    }
    if (pageInfo) {
      pageInfo.textContent = 'Page ' + currentPage + ' of ' + totalPages;
    }
    if (pagePrev) {
      pagePrev.disabled = currentPage <= 1;
      pagePrev.classList.toggle('disabled', currentPage <= 1);
    }
    if (pageNext) {
      pageNext.disabled = currentPage >= totalPages;
      pageNext.classList.toggle('disabled', currentPage >= totalPages);
    }
  }

  // Pagination button events
  if (pagePrev) {
    pagePrev.addEventListener('click', function () {
      if (currentPage > 1) { currentPage--; renderPage(); window.scrollTo({ top: 0, behavior: 'smooth' }); }
    });
  }
  if (pageNext) {
    pageNext.addEventListener('click', function () {
      currentPage++; renderPage(); window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  function applyFilters() {
    currentPage = 1;
    renderPage();
  }

  if (searchInput) {
    searchInput.addEventListener('input', applyFilters);
  }

  // ============================================================
  // Category Filter
  // ============================================================
  const catButtons = document.querySelectorAll('.cat-btn');

  if (catButtons.length > 0) {
    catButtons.forEach(function (btn) {
      btn.addEventListener('click', function () {
        catButtons.forEach(function (b) { b.classList.remove('active'); });
        this.classList.add('active');
        activeCategory = this.getAttribute('data-category');
        applyFilters();
      });
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

        if (this.classList.contains('active')) {
          this.classList.remove('active');
          activeTag = '';
        } else {
          tagButtons.forEach(function (b) { b.classList.remove('active'); });
          this.classList.add('active');
          activeTag = tag;
        }
        applyFilters();
      });
    });
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
  // Table of Contents
  // ============================================================
  function buildTOC() {
    var tocNav = document.getElementById('toc-nav');
    var postContent = document.getElementById('post-content');
    if (!tocNav || !postContent) return;

    var headings = postContent.querySelectorAll('h2, h3, h4');
    if (headings.length === 0) {
      var sidebar = document.getElementById('toc-sidebar');
      if (sidebar) sidebar.style.display = 'none';
      return;
    }

    headings.forEach(function (heading, index) {
      if (!heading.id) {
        heading.id = 'heading-' + index;
      }
      var link = document.createElement('a');
      link.href = '#' + heading.id;
      link.className = 'toc-link';
      link.setAttribute('data-level', heading.tagName.charAt(1));
      link.textContent = heading.textContent;
      link.addEventListener('click', function (e) {
        e.preventDefault();
        heading.scrollIntoView({ behavior: 'smooth', block: 'start' });
        var sb = document.getElementById('toc-sidebar');
        if (sb) sb.classList.remove('open');
      });
      tocNav.appendChild(link);
    });

    var tocLinks = tocNav.querySelectorAll('.toc-link');

    function updateActiveHeading() {
      var scrollPos = window.scrollY + 100;
      var current = null;
      headings.forEach(function (h) {
        if (h.offsetTop <= scrollPos) current = h;
      });
      tocLinks.forEach(function (lnk) {
        lnk.classList.remove('active');
        if (current && lnk.getAttribute('href') === '#' + current.id) {
          lnk.classList.add('active');
        }
      });
    }

    window.addEventListener('scroll', updateActiveHeading, { passive: true });
    updateActiveHeading();

    var tocToggle = document.getElementById('toc-toggle');
    var tocSidebar = document.getElementById('toc-sidebar');
    if (tocToggle && tocSidebar) {
      tocToggle.addEventListener('click', function () {
        tocSidebar.classList.toggle('open');
      });
      document.addEventListener('click', function (e) {
        if (!tocSidebar.contains(e.target)) {
          tocSidebar.classList.remove('open');
        }
      });
    }

    var collapseBtn = document.getElementById('toc-collapse-all');
    var topBtn = document.getElementById('toc-top');
    var bottomBtn = document.getElementById('toc-bottom');
    var isCollapsed = false;

    if (collapseBtn) {
      collapseBtn.addEventListener('click', function () {
        var h3links = tocNav.querySelectorAll('.toc-link[data-level="3"], .toc-link[data-level="4"]');
        isCollapsed = !isCollapsed;
        h3links.forEach(function (l) {
          l.style.display = isCollapsed ? 'none' : '';
        });
        collapseBtn.textContent = isCollapsed ? 'Expand all' : 'Collapse all';
      });
    }
    if (topBtn) {
      topBtn.addEventListener('click', function () {
        window.scrollTo({ top: 0, behavior: 'smooth' });
        if (tocSidebar) tocSidebar.classList.remove('open');
      });
    }
    if (bottomBtn) {
      bottomBtn.addEventListener('click', function () {
        window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
        if (tocSidebar) tocSidebar.classList.remove('open');
      });
    }
  }

  // ============================================================
  // Copy button for code blocks
  // ============================================================
  function addCopyButtons() {
    var codeBlocks = document.querySelectorAll('.post-content pre');
    codeBlocks.forEach(function (pre) {
      var btn = document.createElement('button');
      btn.className = 'code-copy-btn';
      btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>Copy';
      btn.addEventListener('click', function () {
        var code = pre.querySelector('code');
        var text = code ? code.textContent : pre.textContent;
        navigator.clipboard.writeText(text).then(function () {
          btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>Copied!';
          btn.classList.add('copied');
          setTimeout(function () {
            btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>Copy';
            btn.classList.remove('copied');
          }, 2000);
        });
      });
      pre.appendChild(btn);
    });
  }

  // ============================================================
  // Initialize
  // ============================================================
  document.addEventListener('DOMContentLoaded', function () {
    renderPage();
    lazyLoadImages();
    animatePostContent();
    setupExternalLinks();
    buildTOC();
    addCopyButtons();
  });

})();
