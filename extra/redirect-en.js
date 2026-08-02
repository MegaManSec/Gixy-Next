(function(){
  try {
    var path = window.location.pathname || '';
    // Normalize multiple slashes
    path = path.replace(/\/+/, '/');
    // If path starts with /en/, redirect to path without /en/
    if (path.indexOf('/en/') === 0) {
      var newPath = path.replace(/^\/en\//, '/');
      var newUrl = newPath + window.location.search + window.location.hash;
      // Use replace to avoid back button loop
      window.location.replace(newUrl);
    }
  } catch (e) {
    // no-op
  }
})();


