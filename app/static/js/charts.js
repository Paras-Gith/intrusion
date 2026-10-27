document.addEventListener("DOMContentLoaded", () => {
  const classEl = document.getElementById("classChart");
  if (classEl) {
    new Chart(classEl, {
      type: "doughnut",
      data: {
        labels: ["Normal", "Attack"],
        datasets: [{
          data: [Number(classEl.dataset.normal), Number(classEl.dataset.attack)],
          backgroundColor: ["#198754", "#dc3545"],
        }],
      },
      options: { maintainAspectRatio: false, plugins: { legend: { position: "bottom" } } },
    });
  }

  const sevEl = document.getElementById("severityChart");
  if (sevEl) {
    new Chart(sevEl, {
      type: "bar",
      data: {
        labels: ["High", "Medium", "Low"],
        datasets: [{
          label: "Alerts",
          data: [Number(sevEl.dataset.high), Number(sevEl.dataset.medium), Number(sevEl.dataset.low)],
          backgroundColor: ["#dc3545", "#ffc107", "#0dcaf0"],
        }],
      },
      options: {
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
      },
    });
  }
});