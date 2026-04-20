const API = "https://inventory-management-2-t0u8.onrender.com";
let users = [];

// LOAD USERS
async function loadUsers() {
    try {
        const res = await fetch(API + "/register");
        if (!res.ok) {
            //alert("Failed to load users");
            return;
        }
        const data = await res.json();
        console.log(data);
        users = data.data || [];
        displayUsers(users);
    } catch (err) {
        console.log("Error loading users:", err);
        alert("Server error while loading users");
    }
}

// DISPLAY USERS
function displayUsers(list) {
    const table = document.getElementById("userTable");
    table.innerHTML = "";

    list.forEach(user => {
        table.innerHTML += `
            <tr>
                <td>${user.name}</td>
                <td>${user.email}</td>
                <td class="active-status">Active</td>
                <td>
                    <button onclick="deleteUser('${user._id}')">Delete</button>
                </td>
            </tr>
        `;
    });
}

// ADD USER
async function addUser() {

    // alert("Hi")
    const name = document.getElementById("name").value.trim();
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value.trim();

    // Validation
    if (!name || !email || !password) {
        alert("All fields are required");
        return;
    }

    // Password validation (same as schema)
    const passwordRegex = /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;
    if (!passwordRegex.test(password)) {
        alert("Password must be strong (8+ chars, A-Z, a-z, number & special char)");
        return;
    }

    const data = { name, email, password };

    try {
        const res = await fetch(API + "/register", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)
        });

        const result = await res.json();

        if (!res.ok) {
            alert(result.message || "Failed to add user");
            return;
        }

        alert("User Added");
        closeForm();
        loadUsers();
    } catch (err) {
        console.log("Error adding user:", err);
        alert("Server error while adding user");
    }
}

// DELETE USER
function deleteUser(id) {
    if (!confirm("Delete this user?")) return;

    // fetch(API + "/users/" + id, {
    //     method: "DELETE",
    //     headers: {
    //         "Authorization": "Bearer " + localStorage.getItem("token")
    //     }
    // })
    // .then(() => loadUsers())
    // .catch(err => console.log("Delete error:", err));

    alert("User deleted");
    users = users.filter(u => u._id !== id);
    displayUsers(users);
}

// SEARCH USER
function searchUser() {
    const value = document.getElementById("search").value.toLowerCase();

    const filtered = users.filter(u =>
        u.name.toLowerCase().includes(value) ||
        u.email.toLowerCase().includes(value)
    );

    displayUsers(filtered);
}

// MODAL
function openForm() {
    document.getElementById("modal").style.display = "block";
}

function closeForm() {
    document.getElementById("modal").style.display = "none";
}

// INIT
loadUsers();