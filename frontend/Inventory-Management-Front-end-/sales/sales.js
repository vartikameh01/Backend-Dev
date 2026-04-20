const API = "https://inventory-management-2-t0u8.onrender.com";
const token = localStorage.getItem("token");

let sales = [];


// LOAD SALES
async function loadSales() {
    try {
        const res = await fetch(API + "/sales");
        if (!res.ok) {
            alert("Failed to load sales");
            return;
        }
        const data = await res.json();

        sales = data.data || [];
        displaySales(sales);

    } catch (err) {
        console.log("Error:", err);
        alert("Server error while loading sales");
    }
}


// DISPLAY SALES
function displaySales(list) {
    const table = document.getElementById("salesTable");
    table.innerHTML = "";

    list.forEach(item => {
        table.innerHTML += `
            <tr>
                <td>#INV-${item._id.slice(-4)}</td>
                <td>${item.date ? new Date(item.date).toDateString() : "-"}</td>
                <td>${item.product?.name || item.product}</td>
                <td>${item.quantity}</td>
                <td>₹${item.price}</td>
                <td>
                    <button onclick="deleteSale('${item._id}')">Delete</button>
                </td>
            </tr>
        `;
    });
}


// ADD SALE
async function addSale() {

    const product = document.getElementById("product").value;
    const quantity = document.getElementById("quantity").value;
    const price = document.getElementById("price").value;

    if (!product || !quantity || !price) {
        alert("Fill all fields");
        return;
    }

    try {

        const res = await fetch(API + "/sale", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + token
            },
            body: JSON.stringify({ product, quantity, price })
        });

        const data = await res.json();

        if (!res.ok) {
            alert(data.message || "Failed to add sale");
            return;
        }

        alert("Sale Added");

        closeForm();
        loadSales();

    } catch (err) {
        console.log(err);
        alert("Server error while adding sale");
    }
}


// DELETE SALE
async function deleteSale(id) {

    if (!confirm("Delete this sale?")) return;

    try {

        const res = await fetch(API + "/sales/" + id, {
            method: "DELETE",
            headers: {
                "Authorization": "Bearer " + token
            }
        });

        if (!res.ok) {
            const data = await res.json();
            alert(data.message || "Failed to delete sale");
            return;
        }

        alert("Sale Deleted");

        loadSales();

    } catch (err) {
        console.log(err);
        alert("Server error while deleting sale");
    }
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


// MAKE BUTTONS WORK
window.openForm = openForm;
window.closeForm = closeForm;
window.addSale = addSale;
window.deleteSale = deleteSale;


// INIT
loadSales();