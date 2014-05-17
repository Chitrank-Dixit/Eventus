(function ($) {
    var model = [
        { name: "Alf", address: "1, a road, a town, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/john.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "Archie", address: "1, a road, a town, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/john.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "Andy", address: "1, a road, a town, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/john.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "Bernard", address: "1, a road, a town, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/john.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "Ben", address: "1, a road, a town, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/john.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "Chris", address: "1, a road, a town, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/john.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "Charles", address: "1, a road, a town, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/john.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "Dermot", address: "1, a road, a town, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/john.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "David", address: "1, a road, a town, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/john.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "Englebert", address: "1, a road, a town, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/john.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "Erwin", address: "1, a road, a town, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/john.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "Fred", address: "3, an avenue, a village, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/fred.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "Freda", address: "4, a street, a suburb, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/jane.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "Gerald", address: "4, a street, a suburb, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/jane.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "Gemma", address: "3, an avenue, a village, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/fred.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "Henry", address: "4, a street, a suburb, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/jane.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "Harold", address: "4, a street, a suburb, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/jane.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "Ivor", address: "4, a street, a suburb, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/jane.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "Ian", address: "4, a street, a suburb, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/jane.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "John", address: "1, a road, a town, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/john.jpg", deleteMe: function () { viewModel.people.remove(this); } },
        { name: "Jane", address: "2, a street, a city, a county, a postcode", tel: "1234567890", site: "www.aurl.com", pic: "/img/jane.jpg", deleteMe: function () { viewModel.people.remove(this); } }
    ],
    viewModel = {
        people: ko.observableArray(model),
        displayButton: ko.observable(true),
        displayForm: ko.observable(false),
        showForm: function () {
            this.displayForm(true).displayButton(false);
        },
        hideForm: function () {
            this.displayForm(false).displayButton(true);
        },
        addPerson: function () {
            this.displayForm(false).displayButton(true).people.push({
                name: $("#name").val(),
                address: $("#address").val(),
                tel: $("#tel").val(),
                site: $("#site").val(),
                pic: "",
                deleteMe: function () { viewModel.people.remove(this); }
            });
        },
        currentPage: ko.observable(0),
        pageSize: ko.observable(5),
        navigate: function (e) {
            var el = e.target;

            if (el.id === "next") {
                if (this.currentPage() < this.totalPages() - 1) {
                    this.currentPage(this.currentPage() + 1);
                }
            } else {
                if (this.currentPage() > 0) {
                    this.currentPage(this.currentPage() - 1);
                }
            }
        },
        filterLetter: ko.observable(""),
        filterTerm: ko.observable(""),
        clearLetter: function () {
            this.filterLetter("");
        },
        clearTerm: function () {
            this.filterTerm("");
            $("#term").val("");
        },
        setTerm: function () {
            this.filterTerm($("#term").val());
        }
    };

    //filtering / searching
    viewModel.filteredPeopleByTerm = ko.dependentObservable(function () {
        var term = this.filterTerm().toLowerCase();

        if (!term) {
            return this.people();
        }

        return ko.utils.arrayFilter(this.people(), function (person) {
            var found = false;

            for (var prop in person) {
                if (typeof (person[prop]) === "string") {
                    if (person[prop].toLowerCase().search(term) !== -1) {
                        found = true;
                        break;
                    }
                }
            }

            return found;
        });

    }, viewModel);

    viewModel.letters = ko.dependentObservable(function () {
        var result = [];

        ko.utils.arrayForEach(this.filteredPeopleByTerm(), function (person) {
            result.push(person.name.charAt(0).toUpperCase());
        });

        return ko.utils.arrayGetDistinctValues(result.sort());
    }, viewModel);

    viewModel.filteredPeople = ko.dependentObservable(function () {
        var letter = this.filterLetter();
        if (!letter) {
            return this.filteredPeopleByTerm();
        }

        return ko.utils.arrayFilter(this.filteredPeopleByTerm(), function (person) {
            return person.name.charAt(0).toUpperCase() === letter;
        });
    }, viewModel);

    //paging
    viewModel.totalPages = ko.dependentObservable(function () {
        return Math.ceil(this.filteredPeople().length / this.pageSize());
    }, viewModel);

    viewModel.showCurrentPage = ko.dependentObservable(function () {
        if (this.currentPage() > this.totalPages()) {
            this.currentPage(this.totalPages() - 1);
        }
        var startIndex = this.pageSize() * this.currentPage();

        return this.filteredPeople().slice(startIndex, startIndex + this.pageSize());
    }, viewModel);

    viewModel.numericPageSize = ko.dependentObservable(function () {
        if (typeof (this.pageSize()) !== "number") {
            this.pageSize(parseInt(this.pageSize()));
        }
    }, viewModel);

    ko.applyBindings(viewModel);
})(jQuery);