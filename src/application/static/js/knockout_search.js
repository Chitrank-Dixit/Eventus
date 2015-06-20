 
var searchViewModel = {
  var self=this;
  var users = [
  { id: 'Jack', name: 'Jack Smith' },
  { id: 'Jill', name: 'Jill Jones' },
  { id: 'Jane', name: 'Jane Chung' }
  ];

  self.users= ko.observableArray([]);
  self.query= ko.observable('');
 
  self.search= function(value) {
    searchViewModel.users.removeAll();
 
    if (value == '') return;
 
    for (var user in users) {
      if (users[user].name.toLowerCase().indexOf(value.toLowerCase()) >= 0) {
        searchViewModel.users.push(users[user]);
      }
    }
  };
};
 
searchViewModel.query.subscribe(searchViewModel.search);