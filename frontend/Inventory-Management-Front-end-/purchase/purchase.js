const API = "https://inventory-management-2-t0u8.onrender.com";
let purchases = [];



// LOAD PURCHASES
async function loadPurchases() {
    try {
        const res = await fetch(API + "/purchase");
        if (!res.ok) {
            alert("Failed to load purchases");
            return;
        }
        const data = await res.json();

        console.log("Purchases:", data);

        purchases = data.data || [];
        displayPurchases(purchases);

    } catch (err) {
        console.log("Error loading purchases:", err);
        alert("Server error while loading purchases");
    }
}


// DISPLAY PURCHASES
function displayPurchases(list) {
    const table = document.getElementById("purchaseTable");
    table.innerHTML = "";

    list.forEach(item => {
        table.innerHTML += `
            <tr>
                <td>${new Date(item.date).toDateString()}</td>
                <td>${item.product?.name || item.product}</td>
                <td>${item.quantity}</td>
                <td>₹${item.price}</td>
                <td>${item.supplier?.name || item.supplier}</td>
                <td>
                    <button onclick="deletePurchase('${item._id}')">Delete</button>
                </td>
            </tr>
        `;
    });
}


// ADD PURCHASE
async function addPurchase() {

    const data = {
        product: document.getElementById("product").value,
        quantity: document.getElementById("quantity").value,
        price: document.getElementById("price").value,
        supplier: document.getElementById("supplier").value
    };

    console.log("Sending purchase:", data);

    try {

        const res = await fetch(API + "/purchase", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + localStorage.getItem("token")
            },
             body: JSON.stringify(data)
        });

        const result = await res.json();
        console.log("Added purchase:", result);

        if (!res.ok) {
            alert(result.message || "Failed to add purchase");
            return;
        }

        alert("Purchase Added");
        closeForm();
        await loadPurchases();
    } catch (err) {
        console.log("Error adding purchase:", err);
        alert("Server error while adding purchase");
    }
}


// DELETE PURCHASE
async function deletePurchase(id) {

    if (!confirm("Delete this purchase?")) return;

    try {

        const res = await fetch(API + "/purchase/" + id, {
            method: "DELETE",
            headers: {
                "Authorization": "Bearer " + localStorage.getItem("token")
            }
        });

        if (!res.ok) {
            const result = await res.json();
            alert(result.message || "Failed to delete purchase");
            return;
        }

        alert("Purchase Deleted");
        await loadPurchases();

    } catch (err) {
        console.log("Delete error:", err);
        alert("Server error while deleting purchase");
    }
}


// SEARCH
function searchPurchase() {
    const value = document.getElementById("search").value.toLowerCase();

    const filtered = purchases.filter(p => {
        const name = (p.product?.name || "").toLowerCase();
        return name.includes(value);
    });

    displayPurchases(filtered);
}


// LOAD PRODUCT OPTIONS
async function loadProductOptions() {
    try {
        const res = await fetch(API + "/getproduct");
        if (!res.ok) return;
        const data = await res.json();
        const select = document.getElementById("product");
        select.innerHTML = '<option value="">Select Product</option>';
        (data.data || []).forEach(p => {
            select.innerHTML += `<option value="${p._id}">${p.name}</option>`;
        });
    } catch (err) {
        console.log("Error loading product options:", err);
    }
}


// MODAL
function openForm() {
    document.getElementById("modal").style.display = "block";
    loadProductOptions();
}

function closeForm() {
    document.getElementById("modal").style.display = "none";
}


// INIT
loadPurchases();