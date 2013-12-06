UserApp AngularJS
=================

Module with AngularJS services and directives that integrates [UserApp](https://www.userapp.io/) into your app.

*UserApp is a cloud-based user management API for web apps with the purpose to relieve developers from having to program logic for user authentication, sign-up, invoicing, feature/property/permission management, and more.*

## Getting Started

1. Include the UserApp JavaScript library and the AngularJS module into your app.

        <script src="https://app.userapp.io/js/userapp.client.js"></script>
        <script src="https://raw.github.com/userapp-io/userapp-angular/master/angularjs.userapp.js"></script>

2. Inject and initiate the service in your root scope using your [App Id](https://help.userapp.io/customer/portal/articles/1322336-how-do-i-find-my-app-id-):

        .run(function($rootScope, user) {
            user.init({ appId: 'YOUR_APP_ID' });
        });

3. Create routes + templates for login and signup, and use the directives to connect them to UserApp:

        $routeProvider.when('/login', {templateUrl: 'partials/login.html'});
        $routeProvider.when('/signup', {templateUrl: 'partials/signup.html'});

4. Set `public` to `true` on the routes you want to make public. And set `login` to `true` on the login route:

        $routeProvider.when('/login', {templateUrl: 'partials/login.html', protected: false, login: true});
        $routeProvider.when('/signup', {templateUrl: 'partials/signup.html', protected: false});

5. Add a log out link:
    
        <a href="#/login" ua-logout>Log Out</a>

6. Hide elements that should only be visible when logged in:

        <div ng-show="user.authorized">Welcome!</div>

7. User the `user` object to access properties on the logged in user:

        <div ng-show="user.authorized">Welcome {{ user.first_name }}!</div>

8. Read this documention and the [UserApp Documentation](https://app.userapp.io/#/docs/) to learn how to use the full API!


## Services

### user

The main service with all session handling etc.

* .init(config)

Initiate the service with your [App Id](https://help.userapp.io/customer/portal/articles/1322336-how-do-i-find-my-app-id-).

        user.init({ appId: 'YOUR_APP_ID' });

* .status()

Returns the status of the session:

        { authorized: false }

* .appId([value])

Sets and gets the App Id.

* .token([value])

Setes and gets the session token.

* .login(user[, callback])

* .logout([callback])

### UserApp

Exposes the UserApp API with the [JavaScript library](https://app.userapp.io/#/docs/libs/javascript/).

## Directives

* ua-login

* ua-logout

* ua-signup

## Example

See example/ for a demo app based on [angular-seed](https://github.com/angular/angular-seed).

## Help

Contact us via email at support@userapp.io or visit our [support center](https://help.userapp.io).

## License

MIT, see LICENSE.




