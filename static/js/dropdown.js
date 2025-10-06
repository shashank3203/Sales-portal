    const toggleBtn = document.getElementById("settingsToggle");
    const dropdownMenu = document.getElementById("dropdownMenu");
    let hideTimeout;

    toggleBtn.addEventListener("click", (e) => {
      e.preventDefault(); // Prevent any default behavior
      dropdownMenu.style.display =
        dropdownMenu.style.display === "block" ? "none" : "block";
    });

    dropdownMenu.addEventListener("mouseenter", () => {
      clearTimeout(hideTimeout);
    });

    dropdownMenu.addEventListener("mouseleave", () => {
      hideTimeout = setTimeout(() => {
        dropdownMenu.style.display = "none";
      }, 3000); // 3 seconds delay
    });

    document.addEventListener("click", (event) => {
      if (
        !document.getElementById("settingsDropdown").contains(event.target) &&
        dropdownMenu.style.display === "block"
      ) {
        dropdownMenu.style.display = "none";
      }
    });