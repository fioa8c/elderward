/* global elderwardAdmin */
(function () {
	'use strict';

	var cfg = window.elderwardAdmin || {};
	var startBtn = document.getElementById('elderward-start');
	var cancelBtn = document.getElementById('elderward-cancel');
	var logInput = document.getElementById('elderward-log');
	var progress = document.getElementById('elderward-progress');
	var bar = progress ? progress.querySelector('.elderward-bar-fill') : null;
	var statusText = document.getElementById('elderward-status-text');
	var stopped = false;

	if (!startBtn) {
		return;
	}

	function post(action, fields) {
		var body = new FormData();
		body.append('action', action);
		body.append('nonce', cfg.nonce);
		Object.keys(fields || {}).forEach(function (key) {
			body.append(key, fields[key]);
		});
		return fetch(cfg.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: body })
			.then(function (response) { return response.json(); });
	}

	function setText(text) {
		if (statusText) {
			statusText.textContent = text;
		}
	}

	function render(data) {
		if (!data) {
			return;
		}
		if (bar) {
			bar.style.width = Math.max(0, Math.min(100, data.percent || 0)) + '%';
		}
		var line = data.stage ? cfg.i18n.running.replace('%s', data.stage) : cfg.i18n.starting;
		if (data.message) {
			line += ' — ' + data.message;
		}
		setText(line);
	}

	function finished(data) {
		startBtn.disabled = false;
		cancelBtn.disabled = true;
		if (data.status === 'done') {
			setText(cfg.i18n.done);
			window.location.reload();
		} else if (data.status === 'failed') {
			setText(cfg.i18n.failed.replace('%s', data.error || ''));
			window.setTimeout(function () { window.location.reload(); }, 1500);
		} else {
			setText(cfg.i18n.cancelled);
			window.setTimeout(function () { window.location.reload(); }, 800);
		}
	}

	function loop() {
		if (stopped) {
			return;
		}
		post('elderward_step').then(function (result) {
			if (!result || !result.success) {
				setText((result && result.data && result.data.message) || cfg.i18n.network);
				window.setTimeout(loop, 3000);
				return;
			}
			var data = result.data;
			render(data);
			if (data.status === 'running') {
				window.setTimeout(loop, 250);
			} else {
				finished(data);
			}
		}).catch(function () {
			setText(cfg.i18n.network);
			window.setTimeout(loop, 3000);
		});
	}

	function begin() {
		stopped = false;
		startBtn.disabled = true;
		cancelBtn.disabled = false;
		progress.hidden = false;
		setText(cfg.i18n.starting);
	}

	startBtn.addEventListener('click', function () {
		begin();
		post('elderward_start', { log: logInput ? logInput.value : '' }).then(function (result) {
			if (!result || !result.success) {
				startBtn.disabled = false;
				cancelBtn.disabled = true;
				setText((result && result.data && result.data.message) || cfg.i18n.network);
				return;
			}
			render(result.data);
			loop();
		}).catch(function () {
			startBtn.disabled = false;
			cancelBtn.disabled = true;
			setText(cfg.i18n.network);
		});
	});

	cancelBtn.addEventListener('click', function () {
		if (!window.confirm(cfg.i18n.confirm)) {
			return;
		}
		stopped = true;
		post('elderward_cancel').then(function (result) {
			finished(result && result.data ? result.data : { status: 'cancelled' });
		});
	});

	// A scan left running (page reload, closed tab) resumes where it stopped.
	if (cfg.status === 'running') {
		begin();
		loop();
	}
})();
