'use strict';


// Declare app level module which depends on filters, and services
angular.module('myApp', [
	'ngRoute',
	'myApp.filters',
	'myApp.services',
	'myApp.directives',
	'myApp.controllers',
	'UserApp'
]).
config(['$routeProvider', function($routeProvider) {
	$routeProvider.when('/login', {templateUrl: 'partials/login.html', login: true});
	$routeProvider.when('/signup', {templateUrl: 'partials/signup.html', public: true});
	$routeProvider.when('/verify-email', {templateUrl: 'partials/verify-email.html', verify_email: true});
	$routeProvider.when('/reset-password', {templateUrl: 'partials/reset-password.html', public: true});
	$routeProvider.when('/set-password', {templateUrl: 'partials/set-password.html', set_password: true});
	$routeProvider.when('/view1', {templateUrl: 'partials/partial1.html', controller: 'MyCtrl1'});
	$routeProvider.when('/view2', {templateUrl: 'partials/partial2.html', controller: 'MyCtrl2'});
	$routeProvider.otherwise({redirectTo: '/view1'});
}])
.run(function($rootScope, user) {
	// Initiate the user service with your UserApp App Id
	// https://help.userapp.io/customer/portal/articles/1322336-how-do-i-find-my-app-id-
	user.init({ appId: 'YOUR-USERAPP-APP-ID' });
});
