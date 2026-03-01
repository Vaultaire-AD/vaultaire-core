// admin_app.js — progressive enhancement for admin pages
function initAdminApp(){
  const root = document.querySelector('.admin-container');
  const header = document.querySelector('.admin-header');

  // Theme handling
  const themeToggle = document.getElementById('theme-toggle');
  function applyTheme(theme){
    if(theme === 'dark') document.body.classList.add('dark');
    else document.body.classList.remove('dark');
  }
  const saved = localStorage.getItem('vaultaire-theme') || 'light';
  applyTheme(saved);
  if(themeToggle){
    themeToggle.addEventListener('click', () => {
      const isDark = document.body.classList.toggle('dark');
      localStorage.setItem('vaultaire-theme', isDark ? 'dark' : 'light');
    });
  }

  // Helper to extract container from full page HTML
  function extractContainer(html){
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');
    return doc.querySelector('.admin-container');
  }

  // AJAX navigation — intercept header nav links
  function ajaxNavigate(url, push){
    if(!url) return;
    showLoading(true);
    fetch(url, {credentials: 'same-origin'})
      .then(r => r.text())
      .then(text => {
        const newCont = extractContainer(text);
        if(newCont && root){
          root.innerHTML = newCont.innerHTML;
          // re-bind forms and internal links
          bindForms();
          // ensure the top of the new content is visible below the fixed header
          scrollToContent();
          if(push) history.pushState({url}, '', url);
        } else {
          // fallback full load
          window.location.href = url;
        }
      }).catch(()=>{ window.location.href = url })
      .finally(()=> showLoading(false));
  }

  // Intercept clicks on header links
  header && header.addEventListener('click', (e) => {
    const a = e.target.closest && e.target.closest('a');
    if(!a) return;
    const href = a.getAttribute('href');
    if(!href) return;
    // only intercept internal admin links (full load for tree page so LDAP tree script runs)
    if(href.startsWith('/admin') && !href.startsWith('/admin/tree') && !href.startsWith('/admin/api/')){
      e.preventDefault();
      ajaxNavigate(href, true);
    }
  });

  // Intercept internal form submits inside admin container and use fetch
  function bindForms(){
    const forms = root ? root.querySelectorAll('form') : [];
    forms.forEach(f => {
      // remove previous listener marker
      if(f.__vaultBound) return;
      f.__vaultBound = true;
      f.addEventListener('submit', (ev) => {
        // allow file uploads and external forms to fallback
        const hasFile = f.querySelector('input[type=file]');
        if(hasFile) return; // don't intercept
        ev.preventDefault();
        const action = f.getAttribute('action') || window.location.pathname + window.location.search;
        const method = (f.getAttribute('method') || 'GET').toUpperCase();
        const formData = new FormData(f);
        showLoading(true);
        fetch(action, {method, body: formData, credentials: 'same-origin'})
          .then(() => {
            // reload the current URL into container
            ajaxNavigate(window.location.pathname + window.location.search, false);
            // after the reload happens, ensure content is visible
            // (ajaxNavigate will call scrollToContent when it replaces the content)
          }).catch(()=>{
            // fallback
            f.submit();
          }).finally(()=> showLoading(false));
      });
    });
  }

  bindForms();
  // Ensure on initial full page load the content top is visible under the header
  // (covers direct visits like /admin/users or /admin/groups?group=)
  // call multiple times to handle late image loads or font layout shifts
  scrollToContent();
  setTimeout(scrollToContent, 80);
  // also re-check after full window load (images, fonts)
  window.addEventListener('load', () => setTimeout(scrollToContent, 40));

  // handle back/forward
  window.addEventListener('popstate', (ev) => {
    const url = (ev.state && ev.state.url) || window.location.href;
    ajaxNavigate(url, false);
  });

  // scroll so the top of the admin container is visible under the fixed header
  function scrollToContent(){
    try{
      if(!root) return;
      const headerRect = header ? header.getBoundingClientRect() : {height:0, top:0, bottom:0};
      const rootRect = root.getBoundingClientRect();
      // compute document Y for the top of the root
      const docTop = window.scrollY + rootRect.top;
      // target is top of root minus header height and a small offset
      const target = Math.max(0, docTop - (headerRect.height || (headerRect.bottom - headerRect.top)) - 8);
      window.scrollTo({ top: target, behavior: 'smooth' });
    } catch(e){ /* ignore */ }
  }

  // loading indicator
  let loader = null;
  function showLoading(on){
    if(on){
      if(!loader){
        loader = document.createElement('div');
        loader.style.position='fixed';
        // place loader just under header
        let topPx = 70;
        try{
          const rect = header.getBoundingClientRect();
          topPx = rect.bottom + 6;
        } catch(e){}
        loader.style.top = topPx + 'px';
        loader.style.right='20px';loader.style.padding='8px 10px';loader.style.background='rgba(0,0,0,0.6)';loader.style.color='#fff';loader.style.borderRadius='6px';loader.innerText='Chargement...';
        document.body.appendChild(loader);
      }
    } else {
      if(loader){ loader.remove(); loader = null }
    }
  }
}

// Initialize now if DOM already parsed, otherwise wait for DOMContentLoaded
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initAdminApp);
} else {
  // script loaded after DOMContentLoaded (safer)
  initAdminApp();
}
