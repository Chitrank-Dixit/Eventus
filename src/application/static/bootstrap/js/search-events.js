$(function() {

    $('#ms').magicSuggest({
        data: '/pop_events1/',
        valueField: 'eventid',
        displayField: 'eventname'
    });

});