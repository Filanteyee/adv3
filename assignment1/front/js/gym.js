var carousel = document.getElementById('gymCarousel');
var textItems = document.querySelectorAll('.carousel-text-item');

carousel.addEventListener('slide.bs.carousel', function (event) {
    textItems.forEach(function (item) {
        item.classList.remove('active');
    });

    var slideIndex = event.to;
    document.getElementById('textSlide' + (slideIndex + 1)).classList.add('active');
});


document.querySelectorAll('.custom-video-container').forEach((container, index) => {
    const video = container.querySelector('video');
    const button = container.querySelector('button');

    button.addEventListener('click', () => {
        if (video.paused) {
            video.play();
            button.classList.add('paused');
        } else {    
            video.pause();
            button.classList.remove('paused');
        }
    });

    video.addEventListener('play', () => button.classList.add('paused'));
    video.addEventListener('pause', () => button.classList.remove('paused'));
});



document.getElementById('hamburger-menu').addEventListener('click', function () {
    const navbarLinks = document.getElementById('navbar-links');

    // Toggle active class for animation
    navbarLinks.classList.toggle('active');
    this.classList.toggle('open'); // Toggle "open" class for hamburger
});


ymaps.ready(function () {
    var map = new ymaps.Map("yandex-map", {
        center: [42.313467, 69.621923],
        zoom: 16,
        controls: []
    });

    map.controls.add('zoomControl', {
        size: 'small'
    });

    var placemark = new ymaps.Placemark([42.313467, 69.621923], {
        balloonContent: '<strong>Beket Batyra 86 </strong><br>Shymkent'
    });

    map.behaviors.enable('drag');
    map.behaviors.disable(['scrollZoom', 'rightMouseButtonMagnifier']);

    map.geoObjects.add(placemark);
});


