const API = "https://inventory-management-2-t0u8.onrender.com";
async function loginUser() {

    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value.trim();

    if (!email || !password) {
        alert("Please fill all fields");
        return;
    }

    try {

        const res = await fetch(API + "/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ email, password })
        });

        const data = await res.json();

        console.log("FULL RESPONSE:", data);

        if (data.data && data.data.token) {

            localStorage.setItem("token", data.data.token);

            localStorage.setItem("userName", data.data.name || "User");
            localStorage.setItem("userRole", data.data.role || "staff");

            alert("Login successful");

            window.location.href = "../dashboard/dashboard.html";

        } else {
            alert(data.message || "Login failed");
        }

    } catch (err) {
        console.log(err);
        alert("Server error");
    }
}