/* Blackbox site - shared behaviour */
(function () {
  // The exploding diagram settles once, on load.
  window.addEventListener('load', function () {
    var fig = document.getElementById('figure');
    if (fig) fig.classList.add('ready');
  });

  // Page transitions.
  // Browsers with cross-document View Transitions animate the navigation
  // themselves (see site.css). For everything else we play a short tape wipe
  // and then follow the link, so the move still feels deliberate.
  var nativeTransitions = 'startViewTransition' in document;

  document.addEventListener('click', function (event) {
    var link = event.target.closest('a[data-transition]');
    if (!link) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
    if (link.target && link.target !== '_self') return;

    if (nativeTransitions) return; // let the browser animate the navigation

    event.preventDefault();
    var href = link.href;
    document.body.classList.add('leaving');
    window.setTimeout(function () {
      window.location.href = href;
    }, 420);
  });
})();
