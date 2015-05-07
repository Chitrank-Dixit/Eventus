// 

/* function showResult(str) {
  if (str.length==0) { 
    document.getElementById("livesearch").innerHTML="";
    document.getElementById("livesearch").style.border="0px";
    return;
  }
  if (window.XMLHttpRequest) {
    // code for IE7+, Firefox, Chrome, Opera, Safari
    xmlhttp=new XMLHttpRequest();
  } else {  // code for IE6, IE5
    xmlhttp=new ActiveXObject("Microsoft.XMLHTTP");
  }
  xmlhttp.onreadystatechange=function() {
    if (xmlhttp.readyState==4 && xmlhttp.status==200) {
      document.getElementById("livesearch").innerHTML=xmlhttp.responseText;
      document.getElementById("livesearch").style.border="1px solid #A5ACB2";
    }
  }
  xmlhttp.open("GET","livesearch.php?q="+str,true);
  xmlhttp.send();
}
*/
$(document).ready(function () {
  // $SCRIPT_ROOT = {{ request.script_root|tojson|safe }};
$(window).load(function(){
        $('#search').keyup(function(){
            var searchField = $('#search').val();
            var regex = new RegExp(searchField, "i");
            var output = '<div class="row">';
            var count = 1;
            $.getJSON('/pop_events1/', function(data) {
              console.log("\n Hello "+data['events']);
              $.each(data, function(key, val){
                
                if ((val.eventname.search(regex) != -1) || (val.creator.search(regex) != -1)) {
                  output += '<div class="col-md-6 well">';
                  output += '<div class="col-md-3"><img class="img-responsive" src="'+val.avatar+'" alt="'+ val.creator +'" /></div>';
                  output += '<div class="col-md-7">';
                  output += '<h5>' + val.eventname + '</h5>';
                  output += '<p>' + val.description + '</p>'
                  output += '</div>';
                  output += '</div>';
                  if(count%2 == 0){
                    output += '</div><div class="row">'
                  }
                  count++;
                }
              });
              output += '</div>';
              $('#results').html(output);
            }); 
        });
      });
});