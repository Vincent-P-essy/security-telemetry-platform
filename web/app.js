"use strict";

async function api(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`${path} -> ${response.status}`);
  return response.json();
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function badge(kind, label) {
  return el("span", `badge ${kind}`, label || kind);
}

function lane(title, rows) {
  const wrap = el("div", "lane");
  wrap.appendChild(el("h3", null, title));
  if (!rows.length) {
    wrap.appendChild(el("div", "empty", "none"));
  } else {
    for (const row of rows) wrap.appendChild(row);
  }
  return wrap;
}

function renderDetail(report) {
  const detail = document.getElementById("detail");
  detail.innerHTML = "";
  detail.appendChild(el("div", "trace-id", `trace_id ${report.trace_id}`));
  const c = report.correlated;

  const spans = c.spans.map((span) => {
    const row = el("div", "span");
    const left = el("span");
    left.appendChild(el("span", "svc", span.service));
    left.append(` ${span.name}`);
    row.appendChild(left);
    row.appendChild(badge(span.status === "error" ? "error" : "ok", span.status));
    return row;
  });

  const logs = c.logs.map((log) => {
    const row = el("div", "log");
    const left = el("span");
    left.appendChild(el("span", "svc", log.service));
    left.append(` ${log.body}`);
    row.appendChild(left);
    return row;
  });

  const alerts = c.alerts.map((alert) => {
    const row = el("div", "alert");
    const left = el("span");
    left.append(`${alert.title} `);
    left.appendChild(el("span", "mono", `(${alert.kind})`));
    row.appendChild(left);
    row.appendChild(badge(alert.severity));
    return row;
  });

  detail.appendChild(lane(`Spans (${spans.length})`, spans));
  detail.appendChild(lane(`Logs (${logs.length})`, logs));
  detail.appendChild(
    lane(
      `Security events (${c.security_events.length})`,
      c.security_events.map((e) => {
        const row = el("div", "alert");
        row.append(`${e.category} `);
        row.appendChild(badge(e.severity));
        return row;
      })
    )
  );
  detail.appendChild(lane(`Alerts (${alerts.length})`, alerts));
}

async function loadScenarios() {
  const [catalogue, summary] = await Promise.all([api("/scenarios"), api("/correlate")]);
  const counts = {};
  for (const r of summary.results) counts[r.name] = r.counts.total_alerts;
  const list = document.getElementById("scenarios");
  list.innerHTML = "";
  for (const scenario of catalogue.scenarios) {
    const item = el("button", "scenario");
    item.type = "button";
    const name = el("div", "name");
    name.append(scenario.name + " ");
    if (counts[scenario.name] !== undefined) {
      name.appendChild(badge(counts[scenario.name] ? "high" : "ok", `${counts[scenario.name]} alerts`));
    }
    item.appendChild(name);
    item.appendChild(el("div", "desc", scenario.description));
    item.addEventListener("click", async () => {
      renderDetail(await api(`/correlate/${scenario.name}`));
    });
    list.appendChild(item);
  }
  document.getElementById("meta").textContent =
    `${catalogue.scenarios.length} scenarios, ${summary.incidents} incidents`;
}

loadScenarios().catch((error) => {
  document.getElementById("subtitle").textContent = `Failed to load: ${error.message}`;
});
