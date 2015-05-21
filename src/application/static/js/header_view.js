function viewModel(){
    this.myMessage=ko.observable('The next big thing'); // Initially blank
    this.fullMessage = ko.computed(function() {
        return "From: Chitrank Dixit " + this.myMessage();
    }, this);
}


            