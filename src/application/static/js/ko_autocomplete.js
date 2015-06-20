
// Array with original data
var remoteData = [{
    name: 'Ernie',
    id: 1
}, {
    name: 'Bert',
    id: 2
}, {
    name: 'Germaine',
    id: 3
}, {
    name: 'Sally',
    id: 4
}, {
    name: 'Daisy',
    id: 5
}, {
    name: 'Peaches',
    id: 6
}];

function SearchViewModel() {
    var self = this;
    
    self.users = remoteData;
    
    self.selectedOption = ko.observable('');
    self.options = self.users.map(function (element) {
        // JQuery.UI.AutoComplete expects label & value properties, but we can add our own
        return {
            label: element.name,
            value: element.id,
            // This way we still have acess to the original object
            object: element
        };
    });
}
