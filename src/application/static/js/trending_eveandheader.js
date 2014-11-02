var headerVM;
var trendingeventsVM;

$(document).ready(function() {

    if ($.isEmptyObject(headerVM)) {
        headerVM = new ExampleViewModel();
        ko.applyBindings(headerVM, document.getElementById("searchsite"));
    }

    if ($.isEmptyObject(trendingeventsVM)) {
        trendingeventsVM = new EventsViewModel();
        ko.applyBindings(trendingeventsVM, document.getElementById("refreshResults"));
    }
});