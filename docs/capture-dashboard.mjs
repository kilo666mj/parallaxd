#!/usr/bin/env node
// Capture a documentation-safe dashboard without using production data.
import { spawn } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";

const chrome = spawn("google-chrome", [
  "--headless", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
  "--remote-debugging-port=9223", "--window-size=1440,1100", "about:blank",
], { stdio: "ignore" });

try {
  let target;
  for (let attempt = 0; attempt < 50; attempt++) {
    try {
      target = (await (await fetch("http://127.0.0.1:9223/json")).json()).find(item => item.type === "page" && item.url === "about:blank");
      if (target) break;
    } catch {}
    await delay(100);
  }
  if (!target) throw new Error("Chrome debugging endpoint did not start");

  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = reject;
  });
  let sequence = 0;
  const pending = new Map();
  ws.onmessage = ({ data }) => {
    const message = JSON.parse(data);
    const waiter = pending.get(message.id);
    if (waiter) {
      pending.delete(message.id);
      waiter(message);
    }
  };
  const send = (method, params = {}) => new Promise(resolve => {
    const id = ++sequence;
    pending.set(id, resolve);
    ws.send(JSON.stringify({ id, method, params }));
  });

  await send("Page.navigate", { url: process.env.PARALLAXD_SCREENSHOT_URL || "http://127.0.0.1:18972/" });
  await delay(3000);
  const ready = await send("Runtime.evaluate", { expression: "({title:document.title,url:location.href,loaded:typeof renderOverview})", returnByValue: true });
  if (ready.result?.result?.value?.loaded !== "function") throw new Error(`dashboard did not load: ${JSON.stringify(ready.result?.result?.value)}`);
  const expression = `
    state.principal={authenticated:true,username:'operator',role:'admin',permissions:[]};
    state.incidents=[]; state.health={status:'ok'};
    document.body.classList.remove('locked');
    identity.textContent='operator · admin';
    username.classList.add('hidden'); password.classList.add('hidden'); login.classList.add('hidden');
    logout.classList.remove('hidden');
    const names=['api-edge','customer-portal','dns-primary','mail-relay','object-storage','status-page','tls-expiry'];
    const checks=names.map((check,i)=>({check,kind:i===2?'dns':i>4?'tls':'http',status:'up',assigned_to:['probe-eu','probe-us','probe-ap'][i%3]}));
    const history=names.map((check,i)=>({check,samples:1280+i*73,up:1277+i*73,down:i%3,unknown:0,availability:1-(i%3)/1400,p95_latency_ms:42+i*17}));
    renderOverview({coordinator:'demo',probers:3,checks,components:[{component:'Public services',status:'up',description:'All critical endpoints corroborated'}]}, {ha:{role:'primary',active:true,replication_lag_ms:184},result_queue:{depth:0},notifications:{pending:0,failures:0}}, history);
    meta.textContent='demo fleet · 3 probers · updated just now';
    document.querySelector('.workspace-grid').scrollIntoView(); window.scrollTo(0,0);
  `;
  const evaluated = await send("Runtime.evaluate", { expression, returnByValue: true });
  if (evaluated.result?.exceptionDetails) throw new Error(JSON.stringify(evaluated.result.exceptionDetails));
  await delay(1000);
  await send("Runtime.evaluate", { expression: `
    const safe=['api-edge','customer-portal','dns-primary','mail-relay','object-storage','status-page','tls-expiry'];
    document.querySelectorAll('.check-row').forEach((row,i)=>{
      row.querySelector('.row-title').textContent=safe[i%safe.length];
      row.querySelector('.row-sub').textContent=i===2?'dns':i>4?'tls':'http';
      const line=row.querySelector('.state-line'); line.className='state-line up';
      const badge=row.querySelector('.badge'); badge.className='badge up'; badge.textContent='up';
      const owner=row.querySelector('.owner-cell'); if(owner)owner.textContent=['probe-eu','probe-us','probe-ap'][i%3];
    });
    meta.textContent='demo fleet · 3 probers · updated just now';
  ` });
  const shot = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
  await writeFile(new URL("images/dashboard-overview.png", import.meta.url), Buffer.from(shot.result.data, "base64"));
  ws.close();
} finally {
  chrome.kill("SIGTERM");
}
