// Beket Batyra Section
const field1 = document.getElementById("field1");
const video1 = document.getElementById("video1");

field1.addEventListener("mouseenter", () => {
    video1.play();
});

field1.addEventListener("mouseleave", () => {
    video1.pause();
});

// Gym Section
const gym = document.getElementById("gym");
const video2 = document.getElementById("video2");

gym.addEventListener("mouseenter", () => {
    video2.play();
});

gym.addEventListener("mouseleave", () => {
    video2.pause();
});

// Orynbaeva Section
const field2 = document.getElementById("field2");
const video3 = document.getElementById("video3");

field2.addEventListener("mouseenter", () => {
    video3.play();
});

field2.addEventListener("mouseleave", () => {
    video3.pause();
});
