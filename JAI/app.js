/* =========================================================================
 * app.js - wires the file picker and the "View Certificate" button to the
 * parser in certificate-parser.js. All work happens in the browser.
 * ========================================================================= */
'use strict';

(function () {
  /* How many days before expiry we start warning the user. */
  const WARNING_DAYS = 30;

  /* Shortcuts to the elements on the page. */
  const fileInput = document.getElementById('cert-file');
  const viewButton = document.getElementById('view-button');
  const message = document.getElementById('message');
  const resultBox = document.getElementById('result');
  const badge = document.getElementById('status-badge');
  const warning = document.getElementById('expiry-warning');

  /* ---------- small helpers ---------------------------------------------- */

  /** Show a normal (grey) message, e.g. what to do next. */
  function showInfo(text) {
    message.textContent = text;
    message.classList.remove('is-error');
    resultBox.hidden = true;
  }

  /** Show a red error message, e.g. the file could not be read. */
  function showError(text) {
    message.textContent = text;
    message.classList.add('is-error');
    resultBox.hidden = true;
  }

  /** Format a date for humans, always in UTC so it does not depend on the PC. */
  function formatDate(date) {
    return date.toLocaleString('en-GB', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit', timeZone: 'UTC',
    }) + ' UTC';
  }

  /** Whole days between now and a later date. */
  function daysUntil(date) {
    return Math.ceil((date.getTime() - Date.now()) / 86400000);
  }

  /**
   * Decide whether the certificate is Valid, Expired or Not yet valid.
   * `notBefore`/`notAfter` are Date objects, `now` is only passed in by tests.
   */
  function checkStatus(notBefore, notAfter, now) {
    const at = now ? now.getTime() : Date.now();
    if (at < notBefore.getTime()) return { label: 'Not yet valid', kind: 'future' };
    if (at > notAfter.getTime()) return { label: 'Expired', kind: 'expired' };
    return { label: 'Valid', kind: 'valid' };
  }

  /* ---------- showing a parsed certificate ------------------------------- */

  function render(info) {
    // Subject: show the common name first because it is the most useful part.
    document.getElementById('d-subject').textContent =
      info.commonName ? info.commonName + ' (' + info.subject + ')' : info.subject || 'Not given';
    document.getElementById('d-issuer').textContent = info.issuer || 'Not given';
    document.getElementById('d-serial').textContent = info.serialNumber || 'Not given';
    document.getElementById('d-notbefore').textContent = formatDate(info.notBefore);
    document.getElementById('d-notafter').textContent = formatDate(info.notAfter);
    document.getElementById('d-version').textContent = info.version;

    // Status badge.
    const status = checkStatus(info.notBefore, info.notAfter);
    badge.textContent = status.label;
    badge.className = 'badge badge--' + status.kind;

    // Warn when the certificate is close to expiring.
    if (status.kind === 'valid') {
      const remaining = daysUntil(info.notAfter);
      if (remaining <= WARNING_DAYS) {
        warning.textContent = 'Warning: this certificate expires in ' +
          remaining + (remaining === 1 ? ' day' : ' days') + ' (' + formatDate(info.notAfter) + ').';
        warning.hidden = false;
      } else {
        warning.hidden = true;
      }
    } else {
      warning.hidden = true;
    }

    message.textContent = 'Certificate read successfully.';
    message.classList.remove('is-error');
    resultBox.hidden = false;
  }

  /* ---------- handling the button ---------------------------------------- */

  function viewCertificate() {
    const file = fileInput.files && fileInput.files[0];
    if (!file) {
      showError('Please choose a certificate file first (.cer, .crt or .pem).');
      return;
    }
    if (file.size === 0) {
      showError('That file is empty. Please choose a different certificate file.');
      return;
    }
    // A quick, friendly check of the file name extension.
    if (!/\.(cer|crt|pem|cert|der)$/i.test(file.name)) {
      showError('Unsupported file type "' + file.name + '". Please choose a .cer, .crt or .pem file.');
      return;
    }

    showInfo('Reading "' + file.name + '" ...');

    // file.arrayBuffer() gives us the raw bytes without uploading anything.
    file.arrayBuffer().then(function (buffer) {
      try {
        render(CertificateParser.parseCertificate(new Uint8Array(buffer)));
      } catch (error) {
        if (error instanceof CertificateParser.CertificateError) {
          showError(error.message);
        } else {
          showError('This file could not be read as a certificate. It may be damaged or in another format.');
        }
      }
    }).catch(function () {
      showError('The file could not be opened. Please try choosing it again.');
    });
  }

  viewButton.addEventListener('click', viewCertificate);

  // Pressing Enter in the file picker should also work.
  fileInput.addEventListener('keydown', function (event) {
    if (event.key === 'Enter') viewCertificate();
  });

  // If the user picks a second file, clear the old result.
  fileInput.addEventListener('change', function () {
    const file = fileInput.files && fileInput.files[0];
    showInfo(file ? 'Selected "' + file.name + '". Now press "View Certificate".' : 'No certificate loaded yet.');
  });
})();
