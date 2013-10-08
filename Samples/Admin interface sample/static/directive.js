angular.module('components', [])

.directive('helloWorld', function(){
	return {
		restrict:'E',
		scope:{
			name:'bind'
		},
		templateUrl: 'temp.html'
		
		
	}
	
})

/**
* HelloApp Module
*
* Description
*/
angular.module('HelloApp', ['components'])



