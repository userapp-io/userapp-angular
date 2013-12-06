UserApp AngularJS
=================

Module with AngularJS services and directives that integrates [UserApp](https://www.userapp.io/) into your app.

*UserApp is a cloud-based user management API for web apps with the purpose to relieve developers from having to program logic for user authentication, sign-up, invoicing, feature/property/permission management, and more.*

## Getting Started

1. Include the UserApp JavaScript library and the AngularJS module into your app.

        <script src="https://app.userapp.io/js/userapp.client.js"></script>
        <script src="https://rawgithub.com/userapp-io/userapp-angular/master/angularjs.userapp.js"></script>

2. Inject and initiate the service in your root scope using your [App Id](https://help.userapp.io/customer/portal/articles/1322336-how-do-i-find-my-app-id-):

        .run(function($rootScope, user) {
            user.init({ appId: 'YOUR_APP_ID' });
        });

3. Create routes + templates for login and signup, and use the directives to connect them to UserApp:

        $routeProvider.when('/login', {templateUrl: 'partials/login.html'});
        $routeProvider.when('/signup', {templateUrl: 'partials/signup.html'});

4. Set `public` to `true` on the routes you want to make public. And set `login` to `true` on the login route:

        $routeProvider.when('/login', {templateUrl: 'partials/login.html', public: true, login: true});
        $routeProvider.when('/signup', {templateUrl: 'partials/signup.html', public: true});

5. Add a log out link:
    
        <a href="#" ua-logout>Log Out</a>

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

Sets and gets the session token (stored in a cookie).

* .signup(user[, callback])

Sign up a user, log in, and redirect to default route.

                user.signup({ login: 'timothy', email: 'timothy.johanssn@userapp.io', password: 't1m0thy' }, function(error, result) {});

* .login(user[, callback])

Log in a user and redirect to default route.

                user.login({ login: 'timothy', password: 't1m0thy' }, function(error, result) {});

* .logout([callback])

Log out the logged in user and redirect to the log in route.
                
                user.logout(function(error, result) {});

### UserApp

Exposes the full UserApp API with the [JavaScript library](https://app.userapp.io/#/docs/libs/javascript/).

## Directives

* ua-login

Add this to a form tag to attach it to the `user.login()` function.

                <form ua-login ua-error="error-msg">
	                <input name="login" placeholder="Username"><br>
	                <input name="password" placeholder="Password" type="password"><br>
	                <button type="submit">Log In</button>
	                <p id="error-msg"></p>
                </form>

* ua-logout

Add this to a log out link to attach it to the `user.logout()` function.

                <a href="#" ua-logout>Log Out</a>

* ua-signup

Add this to a form tag to attach it to the `user.signup()` function. Use `ua-error` to specify an error object. Use `ua-is-email` on the login input to specify that login is the same as email. All input fields must have a name that is matching the [user's properties](https://app.userapp.io/#/docs/user/#properties).

                <form ua-signup ua-error="error-msg">
                        <input name="first_name" placeholder="Name"><br>
	                <input name="login" ua-is-email placeholder="Email"><br>
	                <input name="password" placeholder="Password" type="password"><br>
	                <button type="submit">Create Account</button>
	                <p id="error-msg"></p>
                </form>

## Example

See example/ for a demo app based on [angular-seed](https://github.com/angular/angular-seed).

## Help

Contact us via email at support@userapp.io or visit our [support center](https://help.userapp.io).

## License

MIT, see LICENSE.




