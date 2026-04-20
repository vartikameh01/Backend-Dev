const API = "https://inventory-management-2-t0u8.onrender.com";

// if already logged in go to dashboard
if(localStorage.getItem("token")){
    window.location.href = "../dashboard/dashboard.html";
}

async function registerUser() {

    const name = document.getElementById("name").value.trim();
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value.trim();
    const confirmPassword = document.getElementById("confirmPassword").value.trim();
    const role = document.getElementById("role").value;

    if (!name || !email || !password || !confirmPassword) {
        alert("Please fill all fields");
        return;
    }

    if (password !== confirmPassword) {
        alert("Passwords do not match");
        return;
    }

    // password check
    const passRegex = /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;
    if (!passRegex.test(password)) {
        alert("Password must be 8+ characters with uppercase, lowercase, number and special character (@$!%*?&)");
        return;
    }

    try {

        const res = await fetch(API + "/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ name, email, password, role })
        });

        const data = await res.json();

        if (res.ok) {
            alert("Account created! Please login.");
            window.location.href = "./logging.html";
        } else {
            alert(data.message || "Registration failed");
        }

    } catch (err) {
        console.log(err);
        alert("Server error");
    }
}