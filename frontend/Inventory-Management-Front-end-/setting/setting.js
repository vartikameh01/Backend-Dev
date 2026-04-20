const API = "https://inventory-management-2-t0u8.onrender.com";
console.log("TOKEN:", localStorage.getItem("token"));
function getToken(){
    return localStorage.getItem("token");
}


// LOAD PROFILE DATA
async function loadProfile(){
    try{

        const res = await fetch(API + "/user/profile", {
            headers: {
                "Authorization": "Bearer " + getToken()
            }
        });

        if (!res.ok) {
            const errData = await res.json();
            alert(errData.message || "Failed to load profile");
            return;
        }

        const data = await res.json();
        const user = data.data;

        document.getElementById("name").value = user.name;
        document.getElementById("email").value = user.email;
        document.getElementById("phone").value = user.phone || "";

    }catch(err){
        console.log("Load profile error:", err);
        alert("Server error while loading profile");
    }
}


// SAVE PROFILE
async function saveProfile(){

    const data = {
        name: document.getElementById("name").value,
        email: document.getElementById("email").value,
        phone: document.getElementById("phone").value
    };

    try{

        const res = await fetch(API + "/user/profile", {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + getToken()
            },
            body: JSON.stringify(data)
        });

        const result = await res.json();

        if (!res.ok) {
            alert(result.message || "Failed to update profile");
            return;
        }

        alert("Profile Updated");

    }catch(err){
        console.log("Save profile error:", err);
        alert("Server error while saving profile");
    }
}


// UPDATE PASSWORD
async function updatePassword(){

    const currentPassword = document.getElementById("currentPass").value;
    const newPassword = document.getElementById("newPass").value;
    const confirmPassword = document.getElementById("confirmPass").value;

    if(newPassword !== confirmPassword){
        alert("Passwords do not match");
        return;
    }

    try{

        const res = await fetch(API + "/user/password", {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + getToken()
            },
            body: JSON.stringify({ currentPassword, newPassword })
        });

        const data = await res.json();

        if (!res.ok) {
            alert(data.message || "Failed to update password");
            return;
        }

        alert(data.message || "Password Updated");

    }catch(err){
        console.log("Password error:", err);
        alert("Server error while updating password");
    }
}


// SAVE NOTIFICATIONS
async function saveNotifications(){

    const data = {
        emailNotifications: document.getElementById("emailNotify").checked,
        pushNotifications: document.getElementById("pushNotify").checked,
        lowStockAlerts: document.getElementById("stockAlert").checked
    };

    try{

        const res = await fetch(API + "/user/settings", {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + getToken()
            },
            body: JSON.stringify(data)
        });

        if (!res.ok) {
            const result = await res.json();
            alert(result.message || "Failed to save preferences");
            return;
        }

        alert("Preferences Saved");

    }catch(err){
        console.log("Notification error:", err);
        alert("Server error while saving preferences");
    }
}


// GENERAL SETTINGS
async function saveGeneral(){

    const data = {
        language: document.getElementById("language").value,
        currency: document.getElementById("currency").value
    };

    try{

        const res = await fetch(API + "/user/settings", {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + getToken()
            },
            body: JSON.stringify(data)
        });

        if (!res.ok) {
            const result = await res.json();
            alert(result.message || "Failed to save settings");
            return;
        }

        alert("Settings Saved");

    }catch(err){
        console.log("General settings error:", err);
        alert("Server error while saving settings");
    }
}


// INIT
loadProfile();


window.saveProfile = saveProfile;
window.updatePassword = updatePassword;
window.saveNotifications = saveNotifications;
window.saveGeneral = saveGeneral;