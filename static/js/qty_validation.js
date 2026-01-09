(function () {
  function onReady(fn) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', fn, { once: true });
    } else {
      fn();
    }
  }

  onReady(function () {
    let form = document.getElementById('qty-form');
    if (!form) {
      const candidates = Array.from(document.querySelectorAll('form[method="post"]'));
      form = candidates.find(f => f.querySelector('input[name^="qty_"]')) || null;
    }
    if (!form) return;

    const banner = document.getElementById('qty-errors');
    const qtySelector = 'input[name^="qty_"]';
    const qtyInputs = Array.from(form.querySelectorAll(qtySelector));

    // UX: se valore "0" iniziale, svuota per mostrare il placeholder.
    qtyInputs.forEach(inp => {
      if ((inp.value || '').trim() === '0') inp.value = '';
      inp.addEventListener('focus', () => setTimeout(() => inp.select(), 0));
      inp.addEventListener('input', () => {
        inp.value = (inp.value || '').replace(',', '.');
        inp.classList.remove('is-invalid');
        inp.setAttribute('aria-invalid', 'false');
        if (banner) banner.classList.add('d-none');
      });
    });

    form.addEventListener('submit', function (e) {
      let firstInvalid = null;

      qtyInputs.forEach(inp => {
        const raw = (inp.value || '').replace(',', '.').trim();
        let invalid = false;

        if (raw === '') {
          invalid = true;          // obbligatorio
        } else if (isNaN(Number(raw)) || Number(raw) < 0) {
          invalid = true;          // numero >= 0
        }

        if (invalid) {
          inp.classList.add('is-invalid');
          inp.setAttribute('aria-invalid', 'true');
          if (!firstInvalid) firstInvalid = inp;
        } else {
          inp.classList.remove('is-invalid');
          inp.setAttribute('aria-invalid', 'false');
        }
      });

      if (firstInvalid) {
        e.preventDefault(); // blocca invio
        if (banner) banner.classList.remove('d-none');
        firstInvalid.scrollIntoView({ behavior: 'smooth', block: 'center' });
        firstInvalid.focus({ preventScroll: true });
      }
    });
  });
})();
