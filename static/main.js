$(document).ready(function(){
  $(".header-right > a").click(function() {
    $(".hamburger-menu").addClass("active");

  });
  $(".close").click(function() {
    $(".hamburger-menu").removeClass("active");
    
  });
});

//owl carousel
$(document).ready(function() {
    // Owl Carousel
    var owl = $(".owl-carousel");
    owl.owlCarousel({
        items: 3,
        margin: 10,
        loop: true,
        nav: true,
        autoplay: true,
        autoplayTimeout: 3000,
        onInitialized: function(event) {
        console.log("Owl Carousel initialized");
    },
    onTranslated: function(event) {
        console.log("Owl Carousel translated to item #" + event.item.index);
    },
    onChanged: function(event) {
    console.log("Owl Carousel changed to item #" + event.item.index);
    }
});
});

//modal
const myModal = document.getElementById('myModal')
const myInput = document.getElementById('myInput')

myModal.addEventListener('shown.bs.modal', () => {
  myInput.focus()
})










