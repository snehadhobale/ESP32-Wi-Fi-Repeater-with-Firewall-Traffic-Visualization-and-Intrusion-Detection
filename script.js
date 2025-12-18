// --- Auth ---
document.getElementById("logoutBtn")?.addEventListener("click", () => {
  fetch("/logout").then(() => location.reload());
});

// --- Live MAC table ---
async function refreshMacs() {
  const res = await fetch("/clients");
  if (!res.ok) return;
  const macs = await res.json();
  const tbody = document.querySelector("#macTable tbody");
  tbody.innerHTML = "";
  macs.forEach((mac, i) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${i + 1}</td><td>${mac}</td>`;
    tbody.appendChild(tr);
  });
}
setInterval(refreshMacs, 3000);
refreshMacs();

// --- Traffic mini chart using /get-stats ---
let chart;
async function refreshStats() {
  const res = await fetch("/get-stats");
  if (!res.ok) return;
  const data = await res.json();
  const labels = Object.keys(data);
  const counts = labels.map(k => data[k]?.count || 0);

  const ctx = document.getElementById("trafficChart").getContext("2d");
  if (!chart) {
    chart = new Chart(ctx, {
      type: "bar",
      data: { labels, datasets: [{ label: "Requests / window", data: counts }] },
      options: { responsive: true, scales: { y: { beginAtZero: true } } }
    });
  } else {
    chart.data.labels = labels;
    chart.data.datasets[0].data = counts;
    chart.update();
  }
}
setInterval(refreshStats, 5000);
refreshStats();
/*
// --- Firewall rules view + forms ---
async function loadRules() {
  const r = await fetch("/rules");
  if (r.ok) {
    const t = await r.text();
    document.getElementById("rulesBox").textContent = t;
  }
}
document.getElementById("blockForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  await fetch("/add-rule", { method: "POST", body: fd });
  e.target.reset();
  loadRules();
});
document.getElementById("unblockForm")?.addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  await fetch("/delete-rule", { method: "POST", body: fd });
  e.target.reset();
  loadRules();
});
loadRules();
function fetchData() {
  fetch('/status')
    .then(response => {
      // If ESP32 sends redirect (302), browser may auto-follow → check final URL
      if (response.redirected) {
        window.location.href = response.url; // send user to login page
        return;
      }
      return response.json();
    })
    .then(data => {
      if (!data) return; // prevent errors if redirected

      document.getElementById('status').innerText = data.status;

      let tableBody = document.querySelector("#macTable tbody");
      tableBody.innerHTML = "";

      data.macTable.forEach(entry => {
        let row = document.createElement("tr");
        row.innerHTML = `
          <td>${entry.mac}</td>
          <td>${entry.ip}</td>
          <td>${entry.device}</td>
        `;
        tableBody.appendChild(row);
      });
    })
    .catch(err => console.error("Error fetching data:", err));
}

setInterval(fetchData, 3000);
window.onload = fetchData;
*/