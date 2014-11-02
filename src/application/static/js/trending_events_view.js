function Event(data) {
    console.log(data.eventname);
    this.eventname = ko.observable(data.eventname);
    this.eventid = ko.observable(data.eventid);
    this.description = ko.observable(data.description);
    this.avatar = ko.observable(data.avatar);
    this.creator = ko.observable(data.creator);
    this.creator_id = ko.observable(data.creator_id);
 
}


function EventsViewModel() {
    var self = this;
    self.events = ko.observableArray([]);
    
    $.getJSON("{{ url_for('pop_all_events') }}", function(eventModels) {
        var t = $.map(eventModels.events, function(item) {
            return new Event(item);
            console.log(item);
        });
        self.events(t);

    });

    setInterval(function(){ 
     $.ajax({
     type:"POST",
     data:"Time="+ date,     
     url:"serverRef",
     success: function(data){
         // On success 
                           }
     });              

     },60000);
    
    self.refresh = function() {
        return $.getJSON("{{ url_for('pop_all_events') }}", function(eventModels) {
        var t = $.map(eventModels.events, function(item) {
            return new Event(item);
            console.log(item);
        });
        self.events(t);

      });
    };
  


    self.refresh();
    setTimeout(self.refresh, 1 * 60 * 1000);


}





