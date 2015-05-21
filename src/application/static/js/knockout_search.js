function SearchEvent(data) {
    var self = this;
    self.eventname = ko.observable(data.eventname);
    self.eventid = ko.observable(data.eventid);
    self.description = ko.observable(data.description);
    self.avatar = ko.observable(data.avatar);
    self.creator = ko.observable(data.creator);
    self.creator_id = ko.observable(data.creator_id);
 
}


function SearchEventsViewModel() {
    var self = this;
    self.events = ko.observableArray([]);
    
    $.getJSON("{{ url_for('pop_all_events') }}", function(eventModels) {
        var t = $.map(eventModels.events, function(item) {
            return new Event(item);
            console.log(item);
        });
        self.events(t);

    });

     

    


}
