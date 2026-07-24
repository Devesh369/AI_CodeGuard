/* ==========================================================
   CODEGUARD AUTH JS CONTROLLER
   ========================================================== */

document.addEventListener("DOMContentLoaded", function() {
    // Password visibility toggle helper
    function setupPasswordToggle(inputId, toggleId) {
        const input = document.getElementById(inputId);
        const toggle = document.getElementById(toggleId);

        if (input && toggle) {
            toggle.addEventListener("click", function() {
                const type = input.getAttribute("type") === "password" ? "text" : "password";
                input.setAttribute("type", type);
                this.classList.toggle("fa-eye");
                this.classList.toggle("fa-eye-slash");
            });
        }
    }

    setupPasswordToggle("id_password", "togglePassword");
    setupPasswordToggle("id_password1", "togglePassword1");
    setupPasswordToggle("id_password2", "togglePassword2");
});
