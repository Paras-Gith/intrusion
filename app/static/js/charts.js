// Charts for the results page: traffic split (doughnut) and alerts by severity (bar).
document.addEventListener("DOMContentLoaded", () => {
  if (typeof Chart === "undefined") return;
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  Chart.defaults.font.family = '"IBM Plex Sans", system-ui, sans-serif';
  Chart.defaults.color = "#4A5B6C";
  Chart.defaults.animation = reduceMotion ? false : { duration: 600 };

  // Writes the attack share in the middle of the doughnut
  const centerText = {
    id: "centerText",
    afterDraw(chart, _args, opts) {
      if (!opts || !opts.text) return;
      const { ctx, chartArea } = chart;
      const x = (chartArea.left + chartArea.right) / 2;
      const y = (chartArea.top + chartArea.bottom) / 2;
      ctx.save();
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillStyle = "#10233A";
      ctx.font = '600 30px "Source Serif 4", Georgia, serif';
      ctx.fillText(opts.text, x, y - 8);
      ctx.fillStyle = "#4A5B6C";
      ctx.font = '13px "IBM Plex Sans", sans-serif';
      ctx.fillText(opts.caption || "", x, y + 17);
      ctx.restore();
    },
  };

  const classEl = document.getElementById("classChart");
  if (classEl) {
    const normal = Number(classEl.dataset.normal);
    const attack = Number(classEl.dataset.attack);
    const total = normal + attack;
    const pct = total ? Math.round((attack / total) * 100) : 0;
    new Chart(classEl, {
      type: "doughnut",
      plugins: [centerText],
      data: {
        labels: ["Normal", "Attack"],
        datasets: [{
          data: [normal, attack],
          backgroundColor: ["#2E8B5B", "#C2253A"],
          borderColor: "#ffffff",
          borderWidth: 2,
        }],
      },
      options: {
        maintainAspectRatio: false,
        cutout: "70%",
        plugins: {
          legend: { position: "bottom", labels: { usePointStyle: true, boxWidth: 8, padding: 16 } },
          centerText: { text: pct + "%", caption: "attacks" },
        },
      },
    });
  }

  const sevEl = document.getElementById("severityChart");
  if (sevEl) {
    new Chart(sevEl, {
      type: "bar",
      data: {
        labels: ["High", "Medium", "Low"],
        datasets: [{
          data: [Number(sevEl.dataset.high), Number(sevEl.dataset.medium), Number(sevEl.dataset.low)],
          backgroundColor: ["#C2253A", "#D98A0B", "#3B78C4"],
          borderRadius: 4,
          barThickness: 26,
        }],
      },
      options: {
        indexAxis: "y",
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: "#E6EBF0" }, border: { display: false } },
          y: { grid: { display: false }, border: { color: "#D5DCE3" } },
        },
      },
    });
  }
});