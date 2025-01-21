// Load Dashboard Metrics
async function loadDashboardMetrics() {
    try {
        const usersResponse = await fetch("http://localhost:8080/admin/users");
        const bookingsResponse = await fetch("http://localhost:8080/admin/bookings");

        const users = await usersResponse.json();
        const bookings = await bookingsResponse.json();

        document.querySelector(".dashboard-metrics .card:nth-child(1)").textContent = `Users: ${users.length}`;
        document.querySelector(".dashboard-metrics .card:nth-child(2)").textContent = `Bookings: ${bookings.length}`;
        document.querySelector(".dashboard-metrics .card:nth-child(3)").textContent = `Emails Sent: 15`; // Placeholder
    } catch (error) {
        console.error("Error loading dashboard metrics:", error);
    }
}

// Load Users
async function loadUsers() {
    const response = await fetch("http://localhost:8080/admin/users");
    const users = await response.json();
    const tableBody = document.getElementById("user-table-body");
    tableBody.innerHTML = ""; // Clear existing rows

    users.forEach(user => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>${user.ID}</td>
            <td>${user.Email}</td>
            <td>
                <button onclick="deleteUser(${user.ID})">Delete</button>
            </td>
        `;
        tableBody.appendChild(row);
    });
}

// Delete User
async function deleteUser(userId) {
    if (confirm("Are you sure you want to delete this user?")) {
        await fetch("http://localhost:8080/admin/users", {
            method: "DELETE",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ID: userId })
        });
        loadUsers(); // Reload users
    }
}

// Add User
document.getElementById("add-user-button").addEventListener("click", () => {
    document.getElementById("add-user-form").style.display = "block";
});

document.getElementById("add-user-form").addEventListener("submit", async event => {
    event.preventDefault();
    const email = document.getElementById("user-email").value;
    const password = document.getElementById("user-password").value;

    await fetch("http://localhost:8080/auth", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ Email: email, Password: password })
    });

    document.getElementById("add-user-form").reset();
    document.getElementById("add-user-form").style.display = "none";
    loadUsers(); // Reload users
});

// Load Bookings
async function loadBookings() {
    const response = await fetch("http://localhost:8080/admin/bookings");
    const bookings = await response.json();
    const tableBody = document.getElementById("booking-table-body");
    tableBody.innerHTML = ""; // Clear existing rows

    bookings.forEach(booking => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>${booking.ID}</td>
            <td>${booking.Date}</td>
            <td>${booking.Time}</td>
            <td>${booking.Field}</td>
            <td>
                <button onclick="deleteBooking(${booking.ID})">Delete</button>
            </td>
        `;
        tableBody.appendChild(row);
    });
}

// Delete Booking
async function deleteBooking(bookingId) {
    if (confirm("Are you sure you want to delete this booking?")) {
        await fetch("http://localhost:8080/bookings", {
            method: "DELETE",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ID: bookingId })
        });
        loadBookings(); // Reload bookings
    }
}

// Send Emails
const emailForm = document.getElementById("email-form");

if (!emailForm.dataset.bound) {
    emailForm.addEventListener("submit", async (event) => {
        event.preventDefault();

        const submitButton = event.target.querySelector("button[type='submit']");
        submitButton.disabled = true; // Disable button to prevent multiple clicks

        const to = document.getElementById("email-to").value;
        const subject = document.getElementById("email-subject").value;
        const body = document.getElementById("email-body").value;
        const fileInput = document.getElementById("email-attachment");
        let fileContent = "";
        let fileName = "";

        if (fileInput && fileInput.files.length > 0) {
            const file = fileInput.files[0];
            fileName = file.name;
            const reader = new FileReader();
            fileContent = await new Promise((resolve) => {
                reader.onload = () => resolve(reader.result.split(",")[1]); // Get Base64 content
                reader.readAsDataURL(file);
            });
        }

        const emailPayload = {
            to,
            subject,
            body,
            file: fileContent,
            fileName,
        };

        try {
            const response = await fetch("http://localhost:8080/admin/email", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(emailPayload),
            });
            const result = await response.json();
            alert(result.message);
        } catch (error) {
            alert("Failed to send email: " + error.message);
        }

        submitButton.disabled = false; // Re-enable button
        emailForm.reset();
    });
    emailForm.dataset.bound = true;
}

// Show Add Booking Form
document.getElementById("add-booking-button").addEventListener("click", () => {
    const form = document.getElementById("add-booking-form");
    form.style.display = form.style.display === "none" ? "block" : "none";
});

// Add Booking
document.getElementById("add-booking-form").addEventListener("submit", async (event) => {
    event.preventDefault();

    const date = document.getElementById("booking-date").value;
    const time = document.getElementById("booking-time").value;
    const field = document.getElementById("booking-field").value;

    // Send POST request to add booking
    await fetch("http://localhost:8080/bookings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ Date: date, Time: time, Field: field })
    });

    // Reset form and reload bookings
    document.getElementById("add-booking-form").reset();
    document.getElementById("add-booking-form").style.display = "none";
    loadBookings();
});

// Initialize Functions
loadDashboardMetrics();
loadUsers();
loadBookings();
