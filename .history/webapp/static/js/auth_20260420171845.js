(function () {
  'use strict';

  function csrfToken() {
    var m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.getAttribute('content') : '';
  }

  function debounce(fn, ms) {
    var t;
    return function () {
      clearTimeout(t);
      var a = arguments;
      t = setTimeout(function () { fn.apply(null, a); }, ms);
    };
  }

  /* ── Login ───────────────────────────────────────────────── */
  var loginForm = document.getElementById('loginForm');
  if (loginForm) {
    var failBanner = document.getElementById('loginFailBanner');
    var warnBanner = document.getElementById('loginWarnBanner');
    var lockBanner = document.getElementById('loginLockBanner');
    var lockTimer = document.getElementById('lockCountdown');
    var forgotToggle = document.getElementById('forgotToggle');
    var forgotPanel = document.getElementById('forgotPanel');
    var forgotForm = document.getElementById('forgotForm');
    var submitBtn = document.getElementById('loginSubmit');
    var failureCount = 0;

    function hideBanners() {
      if (failBanner) failBanner.classList.add('d-none');
      if (warnBanner) warnBanner.classList.add('d-none');
      if (lockBanner) lockBanner.classList.add('d-none');
    }

    function startLockCountdown(iso) {
      if (!lockBanner || !lockTimer || !iso) return;
      lockBanner.classList.remove('d-none');
      var end = Date.parse(iso);
      if (window.__lockIv) clearInterval(window.__lockIv);
      function tick() {
        var now = Date.now();
        var sec = Math.max(0, Math.floor((end - now) / 1000));
        var m = Math.floor(sec / 60);
        var s = sec % 60;
        lockTimer.textContent = m + ':' + (s < 10 ? '0' : '') + s;
        if (sec <= 0) {
          clearInterval(window.__lockIv);
          lockBanner.classList.add('d-none');
        }
      }
      window.__lockIv = setInterval(tick, 1000);
      tick();
    }

    var bodyLock = document.body.getAttribute('data-locked-until');
    if (bodyLock) startLockCountdown(bodyLock);

    if (forgotToggle && forgotPanel) {
      forgotToggle.addEventListener('click', function (e) {
        e.preventDefault();
        forgotPanel.classList.toggle('open');
      });
    }

    if (forgotForm) {
      forgotForm.addEventListener('submit', function (e) {
        e.preventDefault();
        var email = (document.getElementById('forgotEmail') || {}).value || '';
        fetch('/forgot-password', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken(),
            'X-Requested-With': 'XMLHttpRequest'
          },
          body: JSON.stringify({ email: email.trim() })
        }).then(function () {
          var el = document.getElementById('forgotFlash');
          if (el) {
            el.textContent = 'If this email is registered, instructions have been sent.';
            el.classList.remove('d-none');
          }
        }).catch(function () {});
      });
    }

    loginForm.addEventListener('submit', function (e) {
      e.preventDefault();
      hideBanners();
      var fd = new FormData(loginForm);
      fd.set('csrf_token', csrfToken());
      submitBtn.disabled = true;
      var spin = submitBtn.querySelector('.js-btn-spin');
      if (spin) spin.classList.remove('d-none');

      fetch('/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        body: fd
      }).then(function (res) {
        return res.json().then(function (data) {
          return { res: res, data: data };
        });
      }).then(function (o) {
        if (o.res.ok && o.data.ok) {
          window.location.href = o.data.redirect || '/dashboard';
          return;
        }
        var d = o.data || {};
        if (o.res.status === 423 && d.locked_until) {
          startLockCountdown(d.locked_until);
          failureCount = typeof d.failures === 'number' ? d.failures : 5;
          return;
        }
        if (typeof d.failures === 'number') {
          failureCount = d.failures;
        } else {
          failureCount += 1;
        }
        if (failBanner && failureCount >= 1) {
          failBanner.classList.remove('d-none');
        }
        if (warnBanner && failureCount >= 3 && failureCount < 5) {
          warnBanner.classList.remove('d-none');
          warnBanner.textContent = 'Multiple failed attempts detected. ' + (5 - failureCount) + ' more attempt(s) before lockout.';
        }
      }).catch(function () {
        if (failBanner) failBanner.classList.remove('d-none');
      }).finally(function () {
        submitBtn.disabled = false;
        if (spin) spin.classList.add('d-none');
      });
    });
  }

  /* ── Register ────────────────────────────────────────────── */
  var regForm = document.getElementById('registerForm');
  if (regForm) {
    var pw = document.getElementById('regPassword');
    var pw2 = document.getElementById('regPassword2');
    var strengthEl = document.getElementById('pwStrength');
    var strengthLabel = document.getElementById('pwStrengthLabel');
    var regSubmit = document.getElementById('registerSubmit');
    var regMain = document.getElementById('registerMain');
    var regSuccess = document.getElementById('registerSuccess');

    function strengthClass(p) {
      if (!p || p.length < 8) return 'weak';
      if (/^[a-zA-Z]+$/.test(p) || /^\d+$/.test(p)) return 'fair';
      var hasL = /[a-z]/.test(p);
      var hasU = /[A-Z]/.test(p);
      var hasN = /\d/.test(p);
      var hasS = /[^A-Za-z0-9]/.test(p);
      if (hasL && hasU && hasN && hasS) return 'strong';
      if ((hasL || hasU) && hasN) return 'good';
      if (hasL && hasU) return 'good';
      return 'good';
    }

    function strengthLabelText(cls) {
      if (cls === 'weak') return 'Weak';
      if (cls === 'fair') return 'Fair';
      if (cls === 'good') return 'Good';
      return 'Strong';
    }

    function updateStrength() {
      if (!pw || !strengthEl || !strengthLabel) return;
      var v = pw.value || '';
      var cls = strengthClass(v);
      strengthEl.className = 'pw-strength ' + cls;
      strengthLabel.textContent = strengthLabelText(cls);
    }

    if (pw) {
      pw.addEventListener('input', updateStrength);
      updateStrength();
    }

    function setFieldState(name, state, msg) {
      var fb = document.querySelector('[data-feedback="' + name + '"]');
      var ok = document.querySelector('[data-state="' + name + '"].ok');
      var bad = document.querySelector('[data-state="' + name + '"].bad');
      if (ok) ok.classList.add('d-none');
      if (bad) bad.classList.add('d-none');
      if (fb) {
        fb.textContent = msg || '';
        fb.classList.remove('is-invalid');
        if (state === 'invalid') fb.classList.add('is-invalid');
      }
      if (state === 'ok' && ok) ok.classList.remove('d-none');
      if (state === 'bad' && bad) bad.classList.remove('d-none');
      if (state === 'invalid' && bad && msg) bad.classList.remove('d-none');
    }

    var checkUser = debounce(function () {
      var el = document.getElementById('regUsername');
      if (!el) return;
      var u = el.value.trim();
      if (!/^[a-zA-Z0-9]+$/.test(u)) {
        setFieldState('username', 'invalid', 'Alphanumeric only.');
        return;
      }
      fetch('/check-username?u=' + encodeURIComponent(u))
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (d.invalid) setFieldState('username', 'invalid', 'Invalid username.');
          else if (d.available) setFieldState('username', 'ok', '');
          else setFieldState('username', 'bad', 'Username is taken.');
        });
    }, 300);

    var checkMail = debounce(function () {
      var el = document.getElementById('regEmail');
      if (!el) return;
      var em = el.value.trim();
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) {
        setFieldState('email', 'invalid', 'Invalid email format.');
        return;
      }
      fetch('/check-email?e=' + encodeURIComponent(em))
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (d.invalid) setFieldState('email', 'invalid', 'Invalid email.');
          else if (d.available) setFieldState('email', 'ok', '');
          else setFieldState('email', 'bad', 'Email already registered.');
        });
    }, 300);

    var userEl = document.getElementById('regUsername');
    if (userEl) userEl.addEventListener('blur', checkUser);
    var emailEl = document.getElementById('regEmail');
    if (emailEl) emailEl.addEventListener('blur', checkMail);

    function matchPw() {
      if (!pw || !pw2) return;
      var a = pw.value;
      var b = pw2.value;
      if (!b) {
        setFieldState('confirm', '', '');
        return;
      }
      if (a === b && a.length >= 8) setFieldState('confirm', 'ok', '');
      else if (a !== b) setFieldState('confirm', 'invalid', 'Passwords do not match.');
      else setFieldState('confirm', 'invalid', 'Use at least 8 characters.');
    }
    if (pw2) {
      pw2.addEventListener('blur', matchPw);
      pw.addEventListener('input', function () { if (pw2.value) matchPw(); });
    }

    regForm.addEventListener('submit', function (e) {
      e.preventDefault();
      var terms = document.getElementById('regTerms');
      if (terms && !terms.checked) {
        var tf = document.querySelector('[data-feedback="terms"]');
        if (tf) {
          tf.textContent = 'You must accept the terms.';
          tf.classList.add('is-invalid');
        }
        return;
      }
      var fd = new FormData(regForm);
      fd.set('csrf_token', csrfToken());
      regSubmit.disabled = true;
      var spin = regSubmit.querySelector('.js-btn-spin');
      if (spin) spin.classList.remove('d-none');

      fetch('/register', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
        body: fd
      }).then(function (res) {
        return res.json().then(function (data) {
          return { res: res, data: data };
        }).catch(function () {
          return { res: res, data: {} };
        });
      }).then(function (o) {
        if (o.res.ok && o.data.ok) {
          if (regMain) regMain.classList.add('d-none');
          if (regSuccess) regSuccess.classList.remove('d-none');
          setTimeout(function () {
            window.location.href = o.data.redirect || '/dashboard';
          }, 2000);
          return;
        }
        var errs = (o.data && o.data.errors) || [];
        var box = document.getElementById('registerErrors');
        if (box) {
          box.innerHTML = errs.map(function (x) { return '<div class="auth-inline-error">' + x + '</div>'; }).join('');
          box.classList.remove('d-none');
        }
      }).finally(function () {
        regSubmit.disabled = false;
        if (spin) spin.classList.add('d-none');
      });
    });
  }

  /* ── Password Toggle (All Pages) ────────────────────────── */
  document.querySelectorAll('.js-toggle-pw').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var id = btn.getAttribute('data-target');
      var inp = document.getElementById(id);
      if (!inp) return;
      inp.type = inp.type === 'password' ? 'text' : 'password';
    });
  });
})();
