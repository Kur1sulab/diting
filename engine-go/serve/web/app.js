/* Atlas 控制台前端 —— 纯原生 JS，无外部依赖。
   数据全部来自后端实测结果；AI 输出单独标注，不与实测混排。 */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const state = {
    env: null,
    jobs: [],
    cur: null,        // 当前任务快照
    tab: 'ports',
    filter: '',
    es: null,
    logs: [],
  };

  // ── 中文映射：界面绝不泄漏英文枚举值 ──────────────────────────
  const JOB_STATUS = { queued: '排队中', running: '执行中', done: '已完成', failed: '失败', stopped: '已停止' };
  const STEP_STATUS = { pending: '待执行', running: '执行中', done: '已完成', failed: '失败', skipped: '跳过' };
  const RISK = { high: '高危', medium: '中危', low: '低危', info: '信息' };
  const VERDICT = {
    open: '可访问', exists: '存在', leak: '泄漏', backup: '备份文件', listable: '可列目录',
    swagger: '接口文档', debug: '调试信息', git: '源码泄漏', env: '配置泄漏', soft404: '软 404',
    normal: '正常', sensitive: '敏感', unauthorized: '未授权', ok: '正常',
  };
  const cjk = (map, v, dflt = '—') => {
    if (v === null || v === undefined || v === '') return dflt;
    return map[String(v).toLowerCase()] || String(v);
  };

  // ── 工具 ───────────────────────────────────────────────────
  const esc = (s) => String(s === null || s === undefined ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

  const clip = (s, n = 42) => {
    const t = String(s === null || s === undefined ? '' : s);
    return t.length > n ? t.slice(0, n) + '…' : t;
  };

  const td = (v, opts = {}) => {
    const raw = v === null || v === undefined || v === '' ? '—' : String(v);
    const isChip = opts.chip;
    const body = isChip ? chip(raw, opts.tone) : esc(clip(raw, opts.n || 46));
    const cls = opts.cls ? ` class="${opts.cls}"` : '';
    const title = raw.length > 18 ? ` title="${esc(raw)}"` : '';
    return `<td${cls}${title}>${body}</td>`;
  };

  const chip = (text, tone = '') => `<span class="tag ${tone}">${esc(text)}</span>`;

  const fmtMs = (ms) => {
    if (!ms && ms !== 0) return '';
    if (ms < 1000) return ms + 'ms';
    if (ms < 60000) return (ms / 1000).toFixed(1) + 's';
    return Math.floor(ms / 60000) + 'm' + Math.round((ms % 60000) / 1000) + 's';
  };

  const hhmmss = (ts) => {
    const d = new Date(ts);
    return [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, '0')).join(':');
  };

  // ── 极简 Markdown 渲染（仅标题/列表/加粗/行内码/引用）─────────
  function renderMD(md) {
    const lines = String(md || '').split(/\r?\n/);
    const out = [];
    let inList = false;
    const inline = (s) => esc(s)
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/(?<!\*)\*([^*\n]+)\*(?!\*)/g, '<em>$1</em>');
    const closeList = () => { if (inList) { out.push('</ul>'); inList = false; } };
    for (const raw of lines) {
      const line = raw.replace(/\s+$/, '');
      if (!line.trim()) { closeList(); continue; }
      const h = line.match(/^(#{1,6})\s+(.*)$/);
      if (h) { closeList(); out.push(`<h3>${inline(h[2])}</h3>`); continue; }
      if (/^>\s?/.test(line)) { closeList(); out.push(`<blockquote>${inline(line.replace(/^>\s?/, ''))}</blockquote>`); continue; }
      const li = line.match(/^\s*(?:[-*+]|\d+[.)])\s+(.*)$/);
      if (li) {
        if (!inList) { out.push('<ul>'); inList = true; }
        out.push(`<li>${inline(li[1])}</li>`);
        continue;
      }
      closeList();
      out.push(`<p>${inline(line)}</p>`);
    }
    closeList();
    return out.join('');
  }

  // ── 后端交互 ───────────────────────────────────────────────
  async function api(path, opts = {}) {
    const res = await fetch(path, {
      headers: { 'Content-Type': 'application/json' },
      ...opts,
    });
    const text = await res.text();
    let body = null;
    try { body = text ? JSON.parse(text) : null; } catch { body = { error: text }; }
    if (!res.ok) throw new Error((body && body.error) || `HTTP ${res.status}`);
    return body;
  }

  // ── 启动 ───────────────────────────────────────────────────
  async function boot() {
    try {
      state.env = await api('/api/env');
      const v = $('ver');
      if (state.env.version) {
        v.textContent = state.env.version;
        v.title = `atlas ${state.env.version} · ${state.env.platform} · ${state.env.go}`;
        v.hidden = false;
      }
      const ai = state.env.ai || {};
      const dot = $('aidot');
      if (ai.ready) {
        dot.className = 'dot ready';
        $('aistate').textContent = `AI 就绪 · ${clip(ai.model, 22)}`;
        $('aistate').title = `${ai.model} @ ${ai.base}`;
      } else {
        dot.className = 'dot off';
        $('aistate').textContent = 'AI 未配置';
        $('aistate').title = ai.note || '';
        $('aibtn').disabled = true;
        $('askq').disabled = true;
      }
      $('topmeta').textContent = `${state.env.platform} · atlas ${state.env.version || ''}`;
    } catch (e) {
      $('topmeta').textContent = '后端未连接';
    }
    await refreshJobs();
  }

  async function refreshJobs() {
    try {
      const r = await api('/api/jobs');
      state.jobs = r.jobs || [];
      renderJobList();
      if (!state.cur && state.jobs.length) selectJob(state.jobs[0].id);
    } catch { /* 忽略 */ }
  }

  function renderJobList() {
    $('jobcount').textContent = state.jobs.length;
    const box = $('joblist');
    if (!state.jobs.length) {
      box.innerHTML = '<div class="table-empty" style="padding:14px 6px">还没有任务</div>';
      return;
    }
    box.innerHTML = state.jobs.map((j) => `
      <div class="jobitem ${state.cur && state.cur.id === j.id ? 'active' : ''}" data-id="${esc(j.id)}">
        <div class="jobitem-t">${esc(j.target)}</div>
        <div class="jobitem-m">
          <span class="dot ${esc(j.status)}"></span>
          <span>${esc(cjk(JOB_STATUS, j.status))}</span>
          <span>·</span>
          <span>${esc(fmtMs(j.elapsed_ms))}</span>
        </div>
      </div>`).join('');
    box.querySelectorAll('.jobitem').forEach((el) => {
      el.onclick = () => selectJob(el.dataset.id);
    });
  }

  async function selectJob(id) {
    if (state.es) { state.es.close(); state.es = null; }
    state.logs = [];
    $('console').innerHTML = '';
    state.cur = await api('/api/jobs/' + encodeURIComponent(id));
    renderAll();
    subscribe(id);
  }

  function subscribe(id) {
    const es = new EventSource('/api/jobs/' + encodeURIComponent(id) + '/events');
    state.es = es;
    es.onmessage = (ev) => {
      let e;
      try { e = JSON.parse(ev.data); } catch { return; }
      if (e.type === 'log' && e.log) {
        state.logs.push(e.log);
        appendLog(e.log);
      } else if (e.type === 'job' && e.job) {
        state.cur = e.job;
        state.logs = e.job.logs || state.logs;
        renderAll(true);
        if (['done', 'failed', 'stopped'].includes(e.job.status)) {
          refreshJobs();
          setTimeout(() => { if (state.es === es) { es.close(); state.es = null; } }, 600);
        }
      } else if (e.type === 'ai' && e.ai && state.cur) {
        state.cur.ai = e.ai;
        renderAI();
      }
    };
    es.onerror = () => { /* EventSource 自动重连；后端关流时静默 */ };
  }

  // ── 渲染 ───────────────────────────────────────────────────
  function renderAll(withLogs) {
    const j = state.cur;
    if (!j) return;
    const st = ['done', 'failed', 'stopped'].includes(j.status);
    $('jobstate').textContent = cjk(JOB_STATUS, j.status);
    $('jobstate').className = 'chip ' + j.status;
    $('topmeta').textContent = `${j.target} · ${cjk(JOB_STATUS, j.status)} · ${fmtMs(j.elapsed_ms)}`;
    $('gobtn').disabled = j.status === 'running' || j.status === 'queued';
    $('stopbtn').hidden = !(j.status === 'running' || j.status === 'queued');
    $('stopbtn').dataset.id = j.id;
    $('aibtn').disabled = !(state.env && state.env.ai && state.env.ai.ready) || !st || !j.result;

    renderSteps(j.steps || []);
    renderStats(j);
    renderTable();
    renderAI();
    renderJobList();
    const outEl = $('outdir');
    if (outEl) {
      outEl.textContent = j.out || '—';
      outEl.title = j.out || '';
    }
    $('reportbtn').hidden = !st; // 跑完才给导出
    if (withLogs) {
      const c = $('console');
      c.innerHTML = '';
      (state.logs || []).forEach(appendLog);
    }
  }

  function renderSteps(steps) {
    const box = $('steps');
    if (!steps.length) {
      box.innerHTML = '<div class="steps-empty">还没有任务——填个目标，开始测绘。</div>';
      return;
    }
    box.innerHTML = steps.map((s) => `
      <div class="step ${esc(s.status)}" title="${esc(s.msg || '')}">
        <span class="dot ${esc(s.status)}"></span>
        <span>${esc(s.name)}</span>
        ${s.count ? `<span class="step-ms">${s.count}</span>` : ''}
        ${s.ms ? `<span class="step-ms">${esc(fmtMs(s.ms))}</span>` : ''}
      </div>`).join('');
  }

  function renderStats(j) {
    const c = j.counters || {};
    const set = (id, val, sub) => {
      $('c-' + id).textContent = val === undefined || val === null ? '—' : val;
      if (sub !== undefined) $('s-' + id).textContent = sub;
    };
    const stepOf = (key) => (j.steps || []).find((s) => s.key === key) || {};
    const isIP = j.kind === 'ip';
    set('subs', isIP ? '—' : c.subs,
      isIP ? 'IP 目标，跳过子域'
        : (c.subs ? `${c.subs} 条（含存活验证）` : cjk(STEP_STATUS, stepOf('subdomain').status, '未开始')));

    const ports = j.result && j.result.ports ? j.result.ports : [];
    const svc = [...new Set(ports.map((p) => p.service).filter(Boolean))].slice(0, 3).join(' · ');
    set('ports', c.ports, c.ports ? (svc || '已探测服务') : cjk(STEP_STATUS, stepOf('ports').status, '未开始'));

    set('paths', c.paths, c.paths ? '可疑路径' : cjk(STEP_STATUS, stepOf('paths').status, '未开始'));

    const apis = j.result && j.result.apis ? j.result.apis : [];
    const hi = apis.filter((a) => a.risk === '高').length;
    const mid = apis.filter((a) => a.risk === '中').length;
    set('apis', c.apis, c.apis ? `高危 ${hi} · 中危 ${mid}` : cjk(STEP_STATUS, stepOf('api').status, '未开始'));
    set('finger', c.finger, c.finger ? (j.result && j.result.finger || []).map((f) => f.name).join(' / ') : '未命中');
    document.querySelectorAll('.stat').forEach((el) => el.classList.remove('hot'));
    if (c.ports) document.querySelectorAll('.stat')[1].classList.add('hot');
  }

  function appendLog(l) {
    const c = $('console');
    const near = c.scrollHeight - c.scrollTop - c.clientHeight < 60;
    const div = document.createElement('div');
    div.className = 'l';
    const lvl = l.lvl || 'info';
    div.innerHTML = `<span class="t">${esc(hhmmss(l.ts))}</span> <span class="${esc(lvl)}">${esc(l.msg)}</span>`;
    c.appendChild(div);
    while (c.childElementCount > 2000) c.removeChild(c.firstChild);
    if (near) c.scrollTop = c.scrollHeight;
  }

  // ── 资产表 ─────────────────────────────────────────────────
  function rows() {
    const j = state.cur;
    if (!j || !j.result) return { head: [], body: [] };
    const r = j.result;
    const f = state.filter.toLowerCase();
    const match = (vals) => !f || vals.some((v) => String(v === null || v === undefined ? '' : v).toLowerCase().includes(f));

    if (state.tab === 'ports') {
      const list = (r.ports || []).filter((p) => match([p.port, p.service, p.banner]));
      return {
        head: ['端口', '服务', 'Banner'],
        body: list.map((p) => `<tr>${td(p.port, { cls: 'k' })}${td(p.service)}${td(p.banner, { n: 70 })}</tr>`),
      };
    }
    if (state.tab === 'paths') {
      const list = (r.paths || []).filter((p) => match([p.path, p.status, p.verdict, p.ctype]));
      return {
        head: ['路径', '状态', '类型', '大小', '判定'],
        body: list.map((p) => `<tr>${td(p.path, { cls: 'k' })}${td(p.status)}${td(p.ctype, { n: 26 })}${td(p.size)}${td(cjk(VERDICT, p.verdict, '—'), { chip: true, tone: 'mint' })}</tr>`),
      };
    }
    if (state.tab === 'apis') {
      const list = (r.apis || []).filter((a) => match([a.path, a.name, a.risk, a.marker]));
      return {
        head: ['端点', '名称', '风险', '状态', '证据标记'],
        body: list.map((a) => `<tr>${td(a.path, { cls: 'k' })}${td(a.name, { n: 30 })}${td(cjk(RISK, a.risk), { chip: true, tone: a.risk === 'high' ? 'danger' : a.risk === 'medium' ? 'warn' : '' })}${td(a.status)}${td(a.marker, { n: 40 })}</tr>`),
      };
    }
    const list = (r.subs || []).filter((s) => match([s.host, (s.ips || []).join(',')]));
    return {
      head: ['主机', 'IP', '存活', 'HTTP'],
      body: list.map((s) => `<tr>${td(s.host, { cls: 'k' })}${td((s.ips || []).join(', '), { n: 30 })}${td(s.alive ? '存活' : '未响应', { chip: true, tone: s.alive ? 'mint' : '' })}${td(s.http && s.http.status ? `${s.http.status} ${cjk(VERDICT, '', '')}`.trim() : '—')}</tr>`),
    };
  }

  function renderTable() {
    const { head, body } = rows();
    const wrap = $('tablewrap');
    if (!body.length) {
      wrap.innerHTML = `<div class="table-empty">${state.cur && state.cur.result ? '这一类暂无命中' : '暂无数据 —— 先跑一次测绘'}</div>`;
      return;
    }
    wrap.innerHTML = `<table><thead><tr>${head.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${body.join('')}</tbody></table>`;
  }

  // ── AI ─────────────────────────────────────────────────────
  function renderAI() {
    const j = state.cur;
    const box = $('aibody');
    if (!j) {
      box.innerHTML = '<div class="ai-empty"><div class="ai-empty-t">还没有任务</div></div>';
      return;
    }
    let html = '';
    if (j.ai && j.ai.markdown) {
      html += `<div class="md">${renderMD(j.ai.markdown)}</div>
        <div class="ai-meta">AI 研判 · ${esc(j.ai.model)} · ${esc(fmtMs(j.ai.ms))} · 仅供参考，实测以上方资产表为准</div>`;
    } else if (j.result) {
      html += `<div class="ai-empty">
        <div class="ai-empty-t">实测已完成，等你点「一键研判」</div>
        <div class="ai-empty-s">模型只读这份实测结果，按可利用性排序并给下一步补测动作。</div></div>`;
    } else {
      html += `<div class="ai-empty">
        <div class="ai-empty-t">跑完一次测绘后，点「一键研判」</div>
        <div class="ai-empty-s">AI 只看实测结果，按可利用性排序，并给出下一步补测动作。</div></div>`;
    }
    if (state.qa && state.qa.length) {
      html += state.qa.map((q) => `<div class="qa"><div class="qa-q">问：${esc(q.q)}</div><div class="md">${renderMD(q.a)}</div></div>`).join('');
    }
    box.innerHTML = html;
    box.scrollTop = 0;
  }

  // ── 事件绑定 ───────────────────────────────────────────────
  $('scanform').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const target = $('target').value.trim();
    if (!target) { $('target').focus(); return; }
    $('gobtn').disabled = true;
    try {
      const job = await api('/api/jobs', { method: 'POST', body: JSON.stringify({ target }) });
      state.cur = job;
      state.qa = [];
      await refreshJobs();
      await selectJob(job.id);
      $('target').value = '';
    } catch (e) {
      $('topmeta').textContent = '启动失败：' + e.message;
      $('gobtn').disabled = false;
    }
  });

  $('stopbtn').addEventListener('click', async () => {
    const id = $('stopbtn').dataset.id;
    if (!id) return;
    $('stopbtn').disabled = true;
    try { state.cur = await api('/api/jobs/' + encodeURIComponent(id) + '/stop', { method: 'POST' }); renderAll(); }
    catch (e) { $('topmeta').textContent = '停止失败：' + e.message; }
    $('stopbtn').disabled = false;
  });

  $('aibtn').addEventListener('click', async () => {
    const j = state.cur;
    if (!j) return;
    $('aibtn').disabled = true;
    $('aibtn').textContent = '研判中…';
    try {
      const rep = await api('/api/ai/analyze', { method: 'POST', body: JSON.stringify({ id: j.id }) });
      j.ai = rep;
      renderAI();
    } catch (e) {
      $('aibody').innerHTML = `<div class="ai-empty"><div class="ai-empty-t">研判失败</div><div class="ai-empty-s">${esc(e.message)}</div></div>`;
    }
    $('aibtn').textContent = '一键研判';
    $('aibtn').disabled = false;
  });

  $('askform').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const q = $('askq').value.trim();
    if (!q || !state.cur) return;
    $('askq').value = '';
    state.qa = state.qa || [];
    const item = { q, a: '思考中…' };
    state.qa.push(item);
    renderAI();
    try {
      const r = await api('/api/ai/ask', { method: 'POST', body: JSON.stringify({ id: state.cur.id, q }) });
      item.a = r.answer;
    } catch (e) {
      item.a = '**失败**：' + e.message;
    }
    renderAI();
  });

  $('tabs').addEventListener('click', (ev) => {
    const btn = ev.target.closest('.tab');
    if (!btn) return;
    state.tab = btn.dataset.tab;
    document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t === btn));
    renderTable();
  });

  $('filter').addEventListener('input', (ev) => {
    state.filter = ev.target.value.trim();
    renderTable();
  });

  $('reportbtn').addEventListener('click', () => {
    if (!state.cur) return;
    window.open('/api/jobs/' + encodeURIComponent(state.cur.id) + '/report.md', '_blank');
  });

  document.querySelectorAll('.nav-item').forEach((b) => {
    b.addEventListener('click', () => {
      document.querySelectorAll('.nav-item').forEach((x) => x.classList.toggle('active', x === b));
      const el = $(b.dataset.jump);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  boot();
})();
