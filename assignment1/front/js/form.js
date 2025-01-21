    // Авторизация
    document.getElementById("login-form").addEventListener("submit", async (event) => {
        event.preventDefault();

        // Получение данных из input полей
        const email = document.getElementById("email").value;
        const password = document.getElementById("password").value;

        // Отправка запроса на сервер
        const response = await fetch("http://localhost:8080/auth", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();
        alert(data.message); // Показываем сообщение пользователю
    });

    // Регистрация
    document.getElementById("register-button").addEventListener("click", async () => {
        // Получение данных из input полей
        const email = document.getElementById("email").value;
        const password = document.getElementById("password").value;

        // Отправка запроса на сервер
        const response = await fetch("http://localhost:8080/auth", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();
        alert(data.message); // Показываем сообщение пользователю
    });
