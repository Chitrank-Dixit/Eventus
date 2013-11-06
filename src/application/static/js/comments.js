$SCRIPT_ROOT = {{ request.script_root|tojson|safe }};

// Knockoutjs Comment Code

function Comment(data) {
    this.comment = ko.observable(data.comment);
    this.name = ko.observable(data.name);
    this.uid = ko.observable(data.uid);

    
}

function Invite(data) {
    this.uname = ko.observable(data.uname);
    this.uuid = ko.observable(data.uuid);
    
    
}

function CommentViewModel() {
    var self = this;
    self.users = ko.observableArray([]);
    self.comments = ko.observableArray([]);
    self.comment = ko.observable();
    
    
    
       
    self.addComment = function() {
        if ( self.comment() != ""){
            self.save();
        }
        self.comment("");
        
        
    };

    $.getJSON("{{ url_for('all_event_comments', eid=eid ) }}", function(commentModels) {
        var t = $.map(commentModels.comments, function(item) {
            return new Comment(item);

        });
        self.comments(t);

    });

    $.getJSON('/users', function(invitationModels) {
        var t = $.map(invitationModels.users, function(item) {
            console.log("Something",item);
            return new Invite(item);
        });
        self.users(t);
    });

    self.save = function() {
        return $.ajax({
            url: "{{ url_for('event_profile', ename = ename , eid = eid ) }}",
            contentType: 'application/json',
            type: 'POST',
            data: JSON.stringify({
                'comment': self.comment(),
                'name' : "{{current_user.name}}",
                'uid' : "{{current_user.id}}",
            }),


            success: function(data) {
                console.log("Pushing to comment array");
                self.comments.push(new Comment({ comment: data.comment, name: data.name, uid: data.uid }));
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

