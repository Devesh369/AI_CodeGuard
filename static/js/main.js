/* ==========================================================
   CODEGUARD AI PLATFORM MAIN JS ENGINE
   ========================================================== */

(function() {
    // 1. Immediate Theme initialization
    if (localStorage.getItem("theme") === "dark") {
        document.documentElement.classList.add("dark");
        document.addEventListener("DOMContentLoaded", function() {
            document.body.classList.add("dark-mode");
        });
    }

    // 2. Clear auth_id on explicit logout flag
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('logout') === 'true') {
        localStorage.removeItem('auth_id');
        const cleanUrl = new URL(window.location.href);
        cleanUrl.searchParams.delete('logout');
        window.history.replaceState({}, document.title, cleanUrl.pathname + cleanUrl.search);
    }

    // 3. Manage auth_id in localStorage for iframe compatibility
    const authId = urlParams.get('auth_id');
    if (authId) {
        localStorage.setItem('auth_id', authId);
    } else {
        const storedAuthId = localStorage.getItem('auth_id');
        if (storedAuthId) {
            const path = window.location.pathname;
            if (path !== '/login' && path !== '/register' && path !== '/logout') {
                const redirectUrl = new URL(window.location.href);
                redirectUrl.searchParams.set('auth_id', storedAuthId);
                window.location.replace(redirectUrl.pathname + redirectUrl.search + redirectUrl.hash);
            }
        }
    }

    // 4. Auto-append auth_id to all internal links and forms
    document.addEventListener("DOMContentLoaded", function() {
        const storedAuthId = localStorage.getItem('auth_id');
        
        function applyAuthToElements() {
            if (!storedAuthId) return;

            document.querySelectorAll('a').forEach(link => {
                const href = link.getAttribute('href');
                if (href && !href.startsWith('http') && !href.startsWith('javascript') && !href.startsWith('#') && !href.includes('auth_id=')) {
                    try {
                        const url = new URL(href, window.location.origin);
                        url.searchParams.set('auth_id', storedAuthId);
                        link.setAttribute('href', url.pathname + url.search + url.hash);
                    } catch (e) {
                        const separator = href.includes('?') ? '&' : '?';
                        link.setAttribute('href', href + separator + 'auth_id=' + storedAuthId);
                    }
                }
            });

            document.querySelectorAll('form').forEach(form => {
                let authInput = form.querySelector('input[name="auth_id"]');
                if (!authInput) {
                    authInput = document.createElement('input');
                    authInput.type = 'hidden';
                    authInput.name = 'auth_id';
                    form.appendChild(authInput);
                }
                authInput.value = storedAuthId;

                const action = form.getAttribute('action') || '';
                if (!action.startsWith('http') && !action.includes('auth_id=')) {
                    const separator = action.includes('?') ? '&' : '?';
                    form.setAttribute('action', action + separator + 'auth_id=' + storedAuthId);
                }
            });
        }

        applyAuthToElements();

        const observer = new MutationObserver(applyAuthToElements);
        observer.observe(document.body, { childList: true, subtree: true });

        // 5. Sidebar Navigation Controller
        const menuBtn = document.getElementById("menu-toggle");
        const sidebar = document.getElementById("sidebar");
        const mainContent = document.getElementById("main-content");

        if (menuBtn) {
            menuBtn.addEventListener("click", function() {
                if (window.innerWidth <= 768) {
                    sidebar.classList.toggle("show");
                } else {
                    sidebar.classList.toggle("collapsed");
                    if (mainContent) mainContent.classList.toggle("expanded");
                }
                menuBtn.classList.toggle("active");
            });
        }

        window.addEventListener("resize", function() {
            if (window.innerWidth > 768) {
                if (sidebar) sidebar.classList.remove("show");
            } else {
                if (sidebar) sidebar.classList.remove("collapsed");
                if (mainContent) mainContent.classList.remove("expanded");
            }
            if (menuBtn) menuBtn.classList.remove("active");
        });

        // 6. Dark / Light Theme Toggle
        const themeBtn = document.getElementById("themeToggle");
        const body = document.body;
        const html = document.documentElement;

        if (themeBtn) {
            if (localStorage.getItem("theme") === "dark") {
                body.classList.add("dark-mode");
                html.classList.add("dark");
                themeBtn.innerHTML = '<i class="fa-solid fa-sun text-yellow-400"></i>';
            }

            themeBtn.addEventListener("click", function() {
                body.classList.toggle("dark-mode");
                html.classList.toggle("dark");
                if (body.classList.contains("dark-mode")) {
                    localStorage.setItem("theme", "dark");
                    themeBtn.innerHTML = '<i class="fa-solid fa-sun text-yellow-400"></i>';
                } else {
                    localStorage.setItem("theme", "light");
                    themeBtn.innerHTML = '<i class="fa-solid fa-moon text-indigo-400"></i>';
                }
            });
        }
    });
})();

/* Global Helper Functions for Upload, Report, Copy Code, and Modals */
function copyCodeToClipboard(button, targetId) {
    const el = document.getElementById(targetId);
    if (!el) return;
    const text = el.innerText || el.textContent;
    navigator.clipboard.writeText(text).then(() => {
        const originalText = button.innerHTML;
        button.innerHTML = '<i class="fa-solid fa-check text-emerald-400"></i> Copied!';
        button.classList.add('bg-emerald-600');
        setTimeout(() => {
            button.innerHTML = originalText;
            button.classList.remove('bg-emerald-600');
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy text: ', err);
    });
}
