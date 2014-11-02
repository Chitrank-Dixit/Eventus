function ExampleViewModel() {
                var self = this;

                

                self.jsFrameworks = ko.observableArray([
                        'Angular',
                        'Canjs',
                        'Batman',
                        'Meteor',
                        'Ember',
                        'Backbone',
                        'Knockout',
                        'Knockback',
                        'Spine',
                        'Sammy',
                        'YUI',
                        'Closure',
                        'jQuery'
                    ]);

                
                
                self.frameworkToAdd = ko.observable("");
                self.addFramework = function() {
                    self.jsFrameworks.push(self.frameworkToAdd());
                };

                self.removeFramework = function(framework) {
                    self.jsFrameworks.remove(framework);
                };

                
            };

            