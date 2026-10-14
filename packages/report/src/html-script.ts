/**
 * Everything here is progressive: the page is complete and readable with scripting
 * off, filters only hide what is already present, and every animation is skipped
 * when the reader has asked for reduced motion. Nothing is ever requested from a
 * network, because this file is opened from a disk that may have none.
 */
export const REPORT_SCRIPT = `
(function(){
  'use strict';
  var reduceMotion = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;
  function motionAllowed(){ return !(reduceMotion && reduceMotion.matches); }

  /* Copy ---------------------------------------------------------- */
  var prompts = {};
  var promptNode = document.getElementById('myrqen-fix-prompts');
  if (promptNode) { try { prompts = JSON.parse(promptNode.textContent || '{}'); } catch (error) { prompts = {}; } }

  var toast = document.getElementById('toast');
  var toastTimer = null;
  function showToast(message){
    if (!toast) return;
    toast.textContent = message;
    toast.setAttribute('data-visible','true');
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function(){ toast.setAttribute('data-visible','false'); }, 1800);
  }

  function fallbackCopy(text){
    var area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly','');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (error) { ok = false; }
    document.body.removeChild(area);
    return ok;
  }

  function copy(text, done){
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function(){ done(true); }, function(){ done(fallbackCopy(text)); });
      return;
    }
    done(fallbackCopy(text));
  }

  document.addEventListener('click', function(event){
    var target = event.target.closest ? event.target.closest('[data-prompt-for],[data-copy-text]') : null;
    if (!target) return;
    var id = target.getAttribute('data-prompt-for');
    var text = id ? prompts[id] : target.getAttribute('data-copy-text');
    if (!text) { showToast('Nothing to copy'); return; }
    var label = target.textContent;
    copy(text, function(ok){
      target.textContent = ok ? 'Copied' : 'Copy failed';
      target.setAttribute('data-done', ok ? 'true' : 'false');
      showToast(ok ? 'Copied to clipboard' : 'Copy failed. Select the text manually.');
      setTimeout(function(){ target.textContent = label; target.removeAttribute('data-done'); }, 1500);
    });
  });

  /* Filtering ------------------------------------------------------ */
  var cards = Array.prototype.slice.call(document.querySelectorAll('.finding'));
  var sections = Array.prototype.slice.call(document.querySelectorAll('[data-findings-section="true"]'));
  var status = document.getElementById('shown-status');
  var emptyState = document.getElementById('filter-empty');
  var filters = { sev:'all', ver:'all', state:'all', component:'all', query:'' };

  function matches(card){
    if (filters.sev !== 'all' && card.getAttribute('data-sev') !== filters.sev) return false;
    if (filters.ver !== 'all' && card.getAttribute('data-ver') !== filters.ver) return false;
    if (filters.state !== 'all' && card.getAttribute('data-state') !== filters.state) return false;
    if (filters.component !== 'all' && card.getAttribute('data-component') !== filters.component) return false;
    if (filters.query && (card.getAttribute('data-search') || '').indexOf(filters.query) === -1) return false;
    return true;
  }

  function apply(animate){
    var shown = 0;
    for (var i = 0; i < cards.length; i++) {
      var card = cards[i];
      var visible = matches(card);
      var wasVisible = !card.hidden;
      card.hidden = !visible;
      if (!visible) continue;
      shown++;
      if (animate && !wasVisible && motionAllowed()) {
        card.classList.remove('enter');
        void card.offsetWidth;
        card.classList.add('enter');
      }
    }
    for (var s = 0; s < sections.length; s++) {
      var section = sections[s];
      if (!section.querySelector('.finding')) continue;
      section.hidden = !section.querySelector('.finding:not([hidden])');
    }
    if (status) status.innerHTML = 'Showing <b>' + shown + '</b> of ' + cards.length + ' findings';
    if (emptyState) emptyState.hidden = shown !== 0 || cards.length === 0;
  }

  document.addEventListener('click', function(event){
    var chip = event.target.closest ? event.target.closest('.chip') : null;
    if (!chip) return;
    var group = chip.getAttribute('data-group');
    var value = chip.getAttribute('data-value');
    if (!group || !value) return;
    filters[group] = value;
    var peers = document.querySelectorAll('.chip[data-group="' + group + '"]');
    for (var i = 0; i < peers.length; i++) peers[i].setAttribute('aria-pressed', String(peers[i] === chip));
    apply(true);
  });

  var search = document.getElementById('finding-search');
  if (search) {
    search.addEventListener('input', function(){
      filters.query = String(search.value || '').trim().toLowerCase();
      apply(true);
    });
  }

  var component = document.getElementById('component-filter');
  if (component) {
    component.addEventListener('change', function(){
      filters.component = component.value;
      apply(true);
    });
  }

  function resetFilters(){
    filters = { sev:'all', ver:'all', state:'all', component:'all', query:'' };
    if (search) search.value = '';
    if (component) component.value = 'all';
    var chips = document.querySelectorAll('.chip');
    for (var i = 0; i < chips.length; i++) {
      chips[i].setAttribute('aria-pressed', String(chips[i].getAttribute('data-value') === 'all'));
    }
    apply(true);
  }

  var clear = document.getElementById('clear-filters');
  if (clear) clear.addEventListener('click', resetFilters);

  /* Expanding ------------------------------------------------------ */
  document.addEventListener('click', function(event){
    if (!event.target.closest) return;
    var head = event.target.closest('summary.fhead');
    if (!head) return;
    if (!motionAllowed() || !window.Element || !Element.prototype.animate) return;
    var details = head.parentNode;
    var body = details.querySelector('.fbody');
    if (!body) return;
    event.preventDefault();
    if (details.open) {
      var height = body.scrollHeight;
      body.style.overflow = 'hidden';
      var closing = body.animate(
        [{ height: height + 'px', opacity: 1 }, { height: '0px', opacity: 0 }],
        { duration: 170, easing: 'ease-in' }
      );
      closing.onfinish = function(){ details.open = false; body.style.overflow = ''; };
      return;
    }
    details.open = true;
    var target = body.scrollHeight;
    body.style.overflow = 'hidden';
    var opening = body.animate(
      [{ height: '0px', opacity: 0 }, { height: target + 'px', opacity: 1 }],
      { duration: 220, easing: 'cubic-bezier(.2,.7,.3,1)' }
    );
    opening.onfinish = function(){ body.style.overflow = ''; };
  });

  /*
   * Counts are printed, not animated. They used to tween up from zero, which is
   * how a screenshot, a print, or a tab opened in the background came to show
   * "Findings 7" on a report with fourteen. A security report's headline number
   * is never allowed to be smaller than the truth, even for a frame.
   */

  /* Section navigation --------------------------------------------- */
  var links = Array.prototype.slice.call(document.querySelectorAll('.toc a'));
  if (links.length > 0 && window.IntersectionObserver) {
    var byId = {};
    var observed = [];
    for (var l = 0; l < links.length; l++) {
      var id = String(links[l].getAttribute('href') || '').slice(1);
      var section = document.getElementById(id);
      if (!section) continue;
      byId[id] = links[l];
      observed.push(section);
    }
    var observer = new IntersectionObserver(function(entries){
      for (var e = 0; e < entries.length; e++) {
        if (!entries[e].isIntersecting) continue;
        for (var k = 0; k < links.length; k++) links[k].removeAttribute('aria-current');
        var active = byId[entries[e].target.id];
        if (active) active.setAttribute('aria-current','true');
      }
    }, { rootMargin: '-12% 0px -70% 0px', threshold: 0 });
    for (var o = 0; o < observed.length; o++) observer.observe(observed[o]);
  }

  /* Deep links ------------------------------------------------------ */
  function revealFromHash(){
    var id = String(window.location.hash || '').slice(1);
    if (!id) return;
    var target = document.getElementById(id);
    if (!target || !target.classList || !target.classList.contains('finding')) return;
    if (target.hidden) resetFilters();
    var details = target.querySelector('.disclosure');
    if (details) details.open = true;
  }
  window.addEventListener('hashchange', revealFromHash);

  /* Printing -------------------------------------------------------- */
  var reopened = [];
  window.addEventListener('beforeprint', function(){
    reopened = [];
    var all = document.querySelectorAll('.disclosure');
    for (var i = 0; i < all.length; i++) {
      if (all[i].open) continue;
      all[i].open = true;
      reopened.push(all[i]);
    }
  });
  window.addEventListener('afterprint', function(){
    for (var i = 0; i < reopened.length; i++) reopened[i].open = false;
    reopened = [];
  });

  apply(false);
  revealFromHash();
})();
`;
