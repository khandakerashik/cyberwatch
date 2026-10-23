/* Reserve the space occupied by the persistent footer and phone navigation.
 * Measuring the rendered bars also handles text zoom, wrapping, and safe areas. */
const footer = document.querySelector('.page-footer');
const navigation = document.querySelector('.sidebar');
const root = document.documentElement;
const phoneLayout = window.matchMedia('(max-width: 640px)');
let queued = false;

function measureBars() {
  queued = false;
  if (!footer || !navigation) return;
  const heights = {
    '--footer-height': Math.ceil(footer.getBoundingClientRect().height),
    '--bottom-nav-height': phoneLayout.matches ? Math.ceil(navigation.getBoundingClientRect().height) : 0,
  };
  for (const [property, height] of Object.entries(heights)) {
    const value = `${height}px`;
    if (root.style.getPropertyValue(property) !== value) root.style.setProperty(property, value);
  }
}

function scheduleMeasurement() {
  if (queued) return;
  queued = true;
  requestAnimationFrame(measureBars);
}

if (footer && navigation) {
  measureBars();
  if ('ResizeObserver' in window) {
    const observer = new ResizeObserver(scheduleMeasurement);
    observer.observe(footer);
    observer.observe(navigation);
  }
  window.addEventListener('resize', scheduleMeasurement, { passive: true });
  phoneLayout.addEventListener('change', scheduleMeasurement);
  document.fonts?.ready.then(scheduleMeasurement);
}
