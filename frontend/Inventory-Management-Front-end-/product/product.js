const API = "https://inventory-management-2-t0u8.onrender.com";
let products = [];


// LOAD PRODUCTS
async function loadProducts() {
    try {
        const res = await fetch(API + "/getproduct");
        if (!res.ok) {
            alert("Failed to load products");
            return;
        }
        const data = await res.json();

        console.log("Products:", data);

        products = data.data || [];
        displayProducts(products);

    } catch (err) {
        console.log("Error loading products:", err);
        alert("Server error while loading products");
    }
}


// DISPLAY PRODUCTS
function displayProducts(list) {
    const table = document.getElementById("productTable");
    table.innerHTML = "";

    list.forEach(p => {
        table.innerHTML += `
            <tr>
                <td>${p.name}</td>
                <td>${p.category || "-"}</td>
                <td>₹${p.price || 0}</td>
                <td>${p.quantity}</td>
                <td>${p.supplier || "-"}</td>
                <td>${p.description || "-"}</td>
                <td>
                    <button onclick="deleteProduct('${p._id}')">Delete</button>
                </td>
            </tr>
        `;
    });
}


// ADD PRODUCT
async function addProduct() {
    const data = {
        name: document.getElementById("name").value,
        category: document.getElementById("category").value,
        price: document.getElementById("price").value,
        quantity: document.getElementById("quantity").value,
        supplier: document.getElementById("supplier").value,
        description: document.getElementById("description").value
    };

    if (!data.name) {
        alert("Product name is required");
        return;
    }

    try {

        const res = await fetch(API + "/product", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + localStorage.getItem("token")
            },
            body: JSON.stringify(data)
        });

        const result = await res.json();
        console.log("Response:", result);

        if (!res.ok) {
            alert(result.message || "Error saving");
            return;
        }

        alert("Product Added");

        closeForm();
        loadProducts();

    } catch (err) {
        console.log("Error:", err);
        alert("Server error");
    }
}

// DELETE PRODUCT
async function deleteProduct(id) {

    if (!confirm("Delete this product?")) return;

    try {

        const res = await fetch(API + "/product/" + id, {
            method: "DELETE",
            headers: {
                "Authorization": "Bearer " + localStorage.getItem("token")
            }
        });

        if (!res.ok) {
            const result = await res.json();
            alert(result.message || "Failed to delete product");
            return;
        }

        alert("Product Deleted");
        loadProducts();

    } catch (err) {
        console.log("Delete error:", err);
        alert("Server error while deleting product");
    }
}


// SEARCH
async function  searchProduct() {
    const value = document.getElementById("search").value.toLowerCase();

    const filtered = products.filter(p =>
        p.name.toLowerCase().includes(value) ||
        (p.category || "").toLowerCase().includes(value)
    );

    displayProducts(filtered);
}


// MODAL
function openForm() {
    document.getElementById("modal").style.display = "block";
}

function closeForm() {
    document.getElementById("modal").style.display = "none";
}


// INIT
loadProducts();