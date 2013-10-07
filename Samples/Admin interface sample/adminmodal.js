angular.module('modalviews',  ['ui.bootstrap']);
// add manager Modal
var addManagerModal = function($scope, $modal) {
  $scope.open = function () {
    var modalInstance = $modal.open({
      templateUrl: 'addManager.html',
      controller: ModalInstanceCtrl});
};
  


};

var ModalInstanceCtrl = function ($scope, $modalInstance) {

  $scope.ok = function () {
    $modalInstance.close();
  };

  $scope.cancel = function () {
    $modalInstance.dismiss('cancel');
  };
};


//add Captain modal

var addCaptainModal = function($scope, $modal) {
  $scope.open = function () {
    var captainModalInstance = $modal.open({
      templateUrl: 'addCaptain.html',
      controller: captainModalInstanceCtrl});
};
  


};

var captainModalInstanceCtrl = function ($scope, $modalInstance) {

  $scope.ok = function () {
    $modalInstance.close();
  };

  $scope.cancel = function () {
    $modalInstance.dismiss('cancel');
  };
};

var addDirectModal = function($scope, $modal) {
  $scope.open = function () {
    var directModalInstance = $modal.open({
      templateUrl: 'addDirect.html',
      controller: directModalInstanceCtrl});
};
  


};

var directModalInstanceCtrl = function ($scope, $modalInstance) {

  $scope.ok = function () {
    $modalInstance.close();
  };

  $scope.cancel = function () {
    $modalInstance.dismiss('cancel');
  };
};


var banManagerModal = function($scope, $modal) {
  $scope.open = function () {
    var banManagerModalInstance = $modal.open({
      templateUrl: 'banManager.html',
      controller: banManagerModalInstanceCtrl});
};
  


};

var banManagerModalInstanceCtrl = function ($scope, $modalInstance) {

  $scope.ok = function () {
    $modalInstance.close();
  };

  $scope.cancel = function () {
    $modalInstance.dismiss('cancel');
  };
};