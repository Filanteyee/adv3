// Создание бронирования
document.getElementById("booking-form").addEventListener("submit", async (event) => {
    event.preventDefault();

    // Получение данных из input полей
    const date = document.getElementById("date").value;
    const time = document.getElementById("time").value;
    const field = document.getElementById("field").value;

    // Отправка запроса на сервер
    const response = await fetch("http://localhost:8080/bookings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ date, time, field })
    });

	
    const data = await response.json();
    alert(data.message); // Показываем сообщение пользователю
});

// Получение всех бронирований
document.getElementById("view-bookings").addEventListener("click", async () => {
    // Отправка запроса на сервер
    const response = await fetch("http://localhost:8080/bookings", {
        method: "GET",
    });

    const bookings = await response.json();

    // Отображение списка бронирований
    const bookingsList = document.getElementById("bookings-list");
    bookingsList.innerHTML = ""; // Очистка старого списка

    bookings.forEach((booking) => {
        const item = document.createElement("div");
        item.textContent = `Дата: ${booking.Date}, Время: ${booking.Time}, Поле: ${booking.Field}`;
        bookingsList.appendChild(item);
    });
});

// Обновление бронирования
document.getElementById("update-booking").addEventListener("click", async () => {
    const id = prompt("Введите ID бронирования для обновления:");
    const date = document.getElementById("date").value;
    const time = document.getElementById("time").value;
    const field = document.getElementById("field").value;

    if (id) {
        // Отправка запроса на сервер
        const response = await fetch("http://localhost:8080/bookings", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ID: parseInt(id), Date: date, Time: time, Field: field })
        });

        const data = await response.json();
        alert(data.message); // Показываем сообщение пользователю
    }
});

// Удаление бронирования
document.getElementById("delete-booking").addEventListener("click", async () => {
    const id = prompt("Введите ID бронирования для удаления:");

    if (id) {
        // Отправка запроса на сервер
        const response = await fetch("http://localhost:8080/bookings", {
            method: "DELETE",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ID: parseInt(id) })
        });

        const data = await response.json();
        alert(data.message); // Показываем сообщение пользователю
    }
});

// Variables for pagination
const bookingsPerPage = 5; // Number of bookings per page
let currentPage = 1; // Current page number
let totalBookings = 0; // Total number of bookings (fetched from server)
let bookings = []; // Array to store fetched bookings

// Function to render bookings for the current page
function renderBookings() {
    const bookingsList = document.getElementById("bookings-list");
    bookingsList.innerHTML = ""; // Clear previous bookings

    // Calculate start and end index for the current page
    const startIndex = (currentPage - 1) * bookingsPerPage;
    const endIndex = Math.min(startIndex + bookingsPerPage, totalBookings);

    // Render the bookings for the current page
    for (let i = startIndex; i < endIndex; i++) {
        const booking = bookings[i];
        const item = document.createElement("div");
        item.textContent = `Дата: ${booking.Date}, Время: ${booking.Time}, Поле: ${booking.Field}`;
        bookingsList.appendChild(item);
    }

    // Render pagination buttons
    renderPaginationButtons();
}

// Function to render pagination buttons
function renderPaginationButtons() {
    const paginationContainer = document.getElementById("pagination-container");
    paginationContainer.innerHTML = ""; // Clear previous buttons

    // Calculate the total number of pages
    const totalPages = Math.ceil(totalBookings / bookingsPerPage);

    // Create buttons dynamically
    for (let i = 1; i <= totalPages; i++) {
        const button = document.createElement("button");
        button.textContent = i;
        button.className = "pagination-button";
        if (i === currentPage) {
            button.classList.add("active");
        }

        // Add event listener to switch pages
        button.addEventListener("click", () => {
            currentPage = i;
            renderBookings();
        });

        paginationContainer.appendChild(button);
    }
}

// Fetch all bookings from the server
async function fetchBookings() {
    const response = await fetch("http://localhost:8080/bookings", {
        method: "GET",
    });

    bookings = await response.json();
    totalBookings = bookings.length;

    // Render bookings and pagination
    renderBookings();
}

// Initialize
fetchBookings();
