// Upload drop zone and the evidence-plot modal.
document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("uploadForm");
  if (form) {
    const input = form.querySelector('input[type="file"]');
    const zone = form.querySelector(".dropzone");
    const nameEl = document.getElementById("dzFile");
    const btn = document.getElementById("analyseBtn");

    const showFile = () => {
      const file = input.files[0];
      nameEl.textContent = file ? file.name : "";
      btn.disabled = !file;
    };
    input.addEventListener("change", showFile);

    ["dragenter", "dragover"].forEach((type) =>
      zone.addEventListener(type, (e) => { e.preventDefault(); zone.classList.add("is-over"); })
    );
    ["dragleave", "drop"].forEach((type) =>
      zone.addEventListener(type, (e) => { e.preventDefault(); zone.classList.remove("is-over"); })
    );
    zone.addEventListener("drop", (e) => {
      if (e.dataTransfer && e.dataTransfer.files.length) {
        input.files = e.dataTransfer.files;
        showFile();
      }
    });

    form.addEventListener("submit", () => {
      btn.querySelector(".spinner-border").classList.remove("d-none");
      btn.querySelector(".btn-label").textContent = "Analysing flows";
      setTimeout(() => { btn.disabled = true; }, 0);
    });
    showFile();
  }

  const modal = document.getElementById("plotModal");
  if (modal) {
    modal.addEventListener("show.bs.modal", (e) => {
      const trigger = e.relatedTarget;
      if (!trigger) return;
      const img = modal.querySelector("img");
      img.src = trigger.dataset.img;
      img.alt = "Waterfall plot explaining flow " + trigger.dataset.row;
      modal.querySelector(".modal-title").textContent = "Why flow " + trigger.dataset.row + " was flagged";
    });
  }
});