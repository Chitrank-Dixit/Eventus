// Knockoutjs Comment Code

function Comment(data) {
    this.comment = ko.observable(data.comment);
    
    
}



function CommentViewModel() {
    var self = this;
    self.comments = ko.observableArray([]);
    self.comment = ko.observable();
    
    
    
       
    self.addComment = function() {
        if ( self.comment() != ""){
            self.save();
        }
        self.comment("");
        
        
    };

    $.getJSON('/comments', function(commentModels) {
        var t = $.map(commentModels.comments, function(item) {
            return new Comment(item);
        });
        self.comments(t);
    });

    self.save = function() {
        return $.ajax({
            url: "{{ url_for('event_profile', ename = ename , eid = eid ) }}",
            contentType: 'application/json',
            type: 'POST',
            data: JSON.stringify({
                'comment': self.comment(),
                
            }),


            success: function(data) {
                console.log("Pushing to comment array");
                self.comments.push(new Comment({ comment: data.comment }));
                return;
            },
            error: function() {
            	console.log(ename);
                return console.log("Failed");
            }
        });
    };
}


// enable validation
// ko.validation.init();

// Activates knockout.js
ko.applyBindings(new CommentViewModel());
