UserApp AngularJS Module
========================

AngularJS module that adds user authentication to your app with [UserApp](https://www.userapp.io/). It supports protected/public routes, rerouting on login/logout, heartbeats for status checks, stores the session token in a cookie, directives for signup/login/logout, OAuth, etc.

*UserApp is a user management API for web & mobile apps with the purpose to relieve developers from having to program logic for user authentication, sign-up, invoicing, feature/property/permission management, and more.*

* [Getting Started](#getting-started)
* [Accessing the logged in user](#accessing-the-logged-in-user)
* [Verify email address](#verify-email-address)
* [Reset password](#reset-password)
* [Access-controlling routes](#access-controlling-routes)
* [Loaders](#loaders)
* [Heartbeats](#heartbeats)
* [Back-end](#back-end)
* [PhoneGap](#phonegap)
* [Services](#services)
* [Directives](#directives)
* [Events](#events)
* [Example](#example)
* [Help](#help)  
* [License](#license)

## Getting Started

Take the [course on Codecademy](http://www.codecademy.com/courses/web-beginner-en-v2b3k)

*or*

1. Include the [UserApp JavaScript library](https://app.userapp.io/#/docs/libs/javascript/) and this AngularJS module in your *index.html*:

  ```html
  <script src="https://app.userapp.io/js/userapp.client.js"></script>
  <script src="https://app.userapp.io/js/angularjs.userapp.js"></script>
  ```

  (You can also install the module with bower: `$ bower install userapp-angular`)

2. Add the `UserApp` module to your app's dependencies (*app.js*):

  ```javascript
  var app = angular.module('myApp', [..., 'UserApp']);
  ```

3. Inject and initiate the service in your `run()` block (*app.js*) with your [App Id](https://help.userapp.io/customer/portal/articles/1322336-how-do-i-find-my-app-id-):

  ```javascript
  app.run(function(user) {
      user.init({ appId: 'YOUR_APP_ID' });
  });
  ```

4. Create routes + templates for login and signup, and use the directives to connect them to UserApp (examples: [login.html](https://github.com/userapp-io/userapp-angular/blob/master/example/partials/login.html) and [signup.html](https://github.com/userapp-io/userapp-angular/blob/master/example/partials/signup.html)):

  ```javascript
  $routeProvider.when('/login', {templateUrl: 'partials/login.html'});
  $routeProvider.when('/signup', {templateUrl: 'partials/signup.html'});
  ```

  **Note:** If you are using [ui-router](https://github.com/angular-ui/ui-router), all you have to do is to create states instead of the routes above.

5. Set `public` to `true` on the routes you want to make public. And set `login` to `true` on the login route:

  ```javascript
  $routeProvider.when('/login', {templateUrl: 'partials/login.html', login: true});
  $routeProvider.when('/signup', {templateUrl: 'partials/signup.html', public: true});
  ```

  The `.otherwise()` route should be set to where you want your users to be redirected after login. Example:

  ```javascript	
  $routeProvider.otherwise({redirectTo: '/home'});
  ```

  **Note:** If you are using [ui-router](https://github.com/angular-ui/ui-router), place the `public` and `login` flags inside `data` instead.

6. Add a log out link:
  
  ```html  
  <a href="#" ua-logout>Log Out</a>
  ```

  (Ends the session and redirects to the login route)

7. Hide elements that should only be visible when logged in:

  ```html
  <div ng-show="user.authenticated">Welcome!</div>
  ```

8. Use the `user` object to access properties on the logged in user:

  ```html
  <div ng-show="user.authenticated">Welcome {{ user.first_name }}!</div>
  ```

  From templates you only use `user`, but to access the logged in user from controllers, use `user.current` or the promise `user.getCurrent()`.

9. Read this documention and the [UserApp Documentation](https://app.userapp.io/#/docs/) to learn how to use the full API!

## Accessing the logged in user

The logged in user has the same fields as the [user profile](https://app.userapp.io/#/docs/user/#properties) in UserApp. See below how to access it.

**From templates**

Access the logged in user profile using the `user` object.

```html
<p>{{ user.first_name }}</p>
```

**From controllers, services, etc.**

To access the logged in user from your controllers, services, etc., use the `current` property on the `user` service like this:

```javascript
var currentUser = user.current;
```

You can also use a promise to ensure that the user is loaded when accessing it, as the user might not have been loaded when your component loads. However, the user will always be loaded when your controller loads (see requirements for ui-router below).

```javascript
user.getCurrent().then(function(currentUser) {
    console.log(currentUser.first_name);
});
```

ui-router requires the `resolve` property to be present on the states that should wait for the user profile to load. An empty object is enough:

```javascript
resolve: {}
```

## Verify email address

To force your new sign-ups to verify their email address, you first need to activate the Email Add-on in UserApp, and then configure the Verification Email.

When this is done, you need to modify your sign up page to show a message to the user after they have signed up. This message should tell them to check their inbox for a verification email.

When a verification email has been sent, the variable `verificationEmailSent` will be set to `true`, so just use `ng-show` to show/hide the message:

```html
<p ng-show="verificationEmailSent">An email has been sent to your inbox. Click on the link to verify your account.</p>
```

This email should be configured to include a link to a route that you will set up with UserApp by adding the `verify_email` flag:

```javascript
$routeProvider.when('/verify-email', {templateUrl: 'partials/verify-email.html', verify_email: true});
```

**Note:** Don't provide this route with a controller, the module will automatically do that. If you want to handle errors, check if the usual `error` object is set.

The template `partials/verify-email.html` could look something like this:

```html
<div ng-show="loading">
    Verifying your email address, please wait...
</div>
<div ng-show="!loading">
    Your email address has been verified, <a href="#/login">click here</a> to log in.
</div>
```

The variable `loading` is set to `true` while the email token is being verified against UserApp.

Now, log in into UserApp and edit the Verification Email to include a link to `http://yourapp.com/#/verify-email?email_token={{email_token}}`,
where "http://yourapp.com" should be replaced with your own address (e.g. "http://localhost").

And that should do it! Try to sign up with your own email address and check that the flow works as it should.

## Reset password

To implement a reset-password functionality together with UserApp's Email Add-on, first make sure that the add-on is enabled and that you have enabled the reset-password email. (Log in->Add-ons->Email).

Then create a new route that will be used for the reset-password form:

```javascript
$routeProvider.when('/reset-password', {templateUrl: 'partials/reset-password.html', public: true});
```

**Note:** Set the `public` flag to `true` so it will be accessible without logging in.

The template `partials/reset-password.html` should consist of a form with an input box for login/username, and a submit button. Something like this:

```html
<form ua-reset-password ng-show="!emailSent">
    <input name="login" placeholder="Username"><br>
    <button type="submit">Send email</button>
        
    <p ng-show="error">{{ error.message }}</p>
</form>
```

```html
<p ng-show="emailSent">An email has been sent to your inbox. Click on the link to set a new password.</p>
```

The directive `ua-reset-password` connects the form to UserApp, with the input named `login` as the login name. When an error occurs, the `error` object will contain more information about it.

When the email has been sent, the variable `emailSent` is set to `true`. Use this to show a friendly message to the user, like in the example above.

Next step is to set up the route which the user will enter the new password. Create a new route with the `set_password` flag set to `true`, like this:

```javascript
$routeProvider.when('/set-password', {templateUrl: 'partials/set-password.html', set_password: true});
```

The template `partials/set-password.html` should consist of a form with an input box for the new password, and a submit button:

```html
<form ua-set-password ng-show="!passwordSaved">
    <input name="new_password" type="password" placeholder="New password"><br>
    <button type="submit">Save password</button>
        
    <p ng-show="error">{{ error.message }}</p>
</form>
```

```html
<p ng-show="passwordSaved">Your new password has been saved, now <a href="#/login">log in</a>!</p>
```

Attach the form to UserApp with the `ua-set-password` directive and an input named `new_password`. Use the `error` object to show errors. When the password has been saved, the variable `passwordSaved` will be set to `true`.

And last, log into UserApp and include a link to the set-password form in the Reset Password email, so something like this: `http://yourapp.com/#/set-password?password_token={{password_token}}`, where "http://yourapp.com" should be replaced with your own address (e.g. "http://localhost").

## Access-controlling routes

Routes/states can be declared as public by setting the `public` property for the route to `true`:

```javascript
$routeProvider.when('/home', { public: true });
```

or when using UI router:

```javascript
$stateProvider.state('home', { data: { public: true } });
```

The `login` route/state, the `verify_email` route/state, and the `set_password` route/state are considered public by default.

If the user is not signed in and accesses a non-public route, the route/state change is prevented and the `authenticationRequiredHandler` is invoked. The default handler transitions to the `login` route. Another handler can be installed like this:
```javascript
user.onAuthenticationRequired(function(route, stateParams) {
   // open login popup, do transition, ...
});
```
For the Angular router the target route is passed to the handler. For the UI router, the target state and the target state parameters are passed.

To add required permissions to a route, use the `hasPermission` property and specify all the permissions as an array, like this:

```javascript
$routeProvider.when('/admin', { templateUrl: 'partials/admin.html', hasPermission: ['admin'] });
```

or as a string, like this:

```javascript
$routeProvider.when('/admin', { templateUrl: 'partials/admin.html', hasPermission: 'admin' });
```

For a more general authorization check, use the `authCheck` property and specify a function that takes the currently logged in user and returns `true` if access to this user should be allowed and `false` if access shall be denied.
```javascript
$routeProvider.when('/admin', { templateUrl: 'partials/admin.html', authCheck: function(user) { 
    return user.properties['abc'] === 'def'
}});
```

If the UI router is used, the state parameters are passed as a second parameter:

```javascript
$stateProvider.state('admin', { data: { public: false, authCheck: function(user, params) { 
    return user.properties['orgId'] === params.id
}}});
```

If access is denied to the logged in user (either because a required permission was not found or `authCheck` returned false), the route/state change is prevented and the `authorizationDeniedHandler` is invoked. The default handler redirects to the default route. Another handler can be installed like this:

```javascript
user.onAccessDenied(function(user, route, stateParams) {
    // show popup, do transition, ...
});
```

For the Angular router the target route is passed as second parameter to the handler. For the UI router, the target state and the target state parameters are passed as parameters two and three.

After a successful login, the default behavior is to transition to the default route. To change this behavior, override the `authenticationSuccessHandler` like this:

```javascript
user.onAuthenticationSuccess(function() {
    // hide popup, do transition, ...
});
```

## Loaders

All directives sets the scope variable `loading` to `true` while it's doing work in the background. This way you could show a loader animation while waiting for the UserApp API to respond. Here's an example with the login form:

```html
<form ua-login>
    <input name="login" placeholder="Username"><br>
    <input name="password" placeholder="Password" type="password"><br>

    <button type="submit">
        <span ng-show="!loading">Log In</span>
        <img ng-show="loading" src="https://app.userapp.io/img/ajax-loader-transparent.gif">
    </button>

    <p ng-show="error">{{ error.message }}</p>
</form>
```

## Heartbeats

The AngularJS module pings the UserApp API with a constant interval to check for status changes and the same time keep the session alive. 
If you want to change the interval these *heartbeats* are made, or turn them off completely, just set the option `heartbeatInterval` to `0`.
The interval is specified in milliseconds and the minimum value is 10 seconds (10000 ms). The default is 20 seconds.

```javascript
user.init({ 
    appId: 'YOUR_APP_ID',
    heartbeatInterval: 0
});
```

## Back-end

Since AngularJS is a front-end framework, all authentication with this module is only done on the client-side, with direct communication with UserApp.

To authorize to your back-end API, you need to provide the session token that was created at login. This token can then be validated against UserApp on the server-side to ensure that the user is authenticated.

If your API/back-end is on the same domain as your Angular app, you can simply get the token from the cookie named `ua_session_token`. If it's not on the same domain, you need to manually provide it with your back-end requests. One solution is to include it with your GET/POST parameters. Another is to use the Authorization header.

Use the `token()` method on the `user` service to obtain the token.

```javascript
var token = user.token();
```

An easy way to add the token to all your requests is to add it as a default header. By listening on the `user.login` and `user.logout` events we can set the header accordingly:

```javascript
$rootScope.$on('user.login', function() {
    $http.defaults.headers.common.Authorization = 'Basic ' + btoa(':' + user.token());
});

$rootScope.$on('user.logout', function() {
    $http.defaults.headers.common.Authorization = null;
});
```

Please note that the `btoa()` function may not be supported by all browsers.

On the back-end, use UserApp's [token.heartbeat()](https://app.userapp.io/#/docs/token/#heartbeat) or [user.get()](https://app.userapp.io/#/docs/user/#get) to verify that the token is valid. The result should then be cached to reduce round-trips to UserApp.

## PhoneGap

This module works perfectly out of the box with [PhoneGap](http://phonegap.com/). 
But if you want persistent sessions (like the Facebook, Twitter, and Instagram apps has), you need to include [userapp-phonegap](https://github.com/userapp-io/userapp-phonegap) into your project.
It will automatically extend the AngularJS module with functionality that sets up persistent sessions.

## Services

### user

>The main service with all session handling etc.

* **user.init(config)**

  Initiate the service with your [App Id](https://help.userapp.io/customer/portal/articles/1322336-how-do-i-find-my-app-id-).

  ```javascript
  user.init({ appId: 'YOUR_APP_ID' });
  ```
  
  Another option is the `heartbeatInterval`, documented [here](#heartbeats).

* **user.status()**

  Returns the status of the session:

  ```javascript
  { authenticated: false }
  ```

* **user.appId([value])**

  Sets and gets the App Id.

* **user.token([value])**

  Sets and gets the session token (stored in a cookie).

* **user.current**

  The logged in user. [See User documentation](https://app.userapp.io/#/docs/user/#properties) for more info. **Note:** This is not a function.

* **user.getCurrent()**
  
  Returns a promise to the logged in user (see above).

  ```javascript
  user.getCurrent().then(function(currentUser) {
      console.log(currentUser.user_id);
  });
  ```

* **user.signup(user[, callback])**

  Sign up a user, log in, and redirect to default route.

  ```javascript
  user.signup({ login: 'timothy', email: 'timothy.johansson@userapp.io', password: 't1m0thy' }, function(error, result) {});
  ```

* **user.login(user[, callback])**

  Log in a user and redirect to default route.

  ```javascript
  user.login({ login: 'timothy', password: 't1m0thy' }, function(error, result) {});
  ```

* **user.logout([callback])**

  Log out the logged in user and redirect to the log in route.
  
  ```javascript              
  user.logout(function(error, result) {});
  ```

* **user.verifyEmail(emailToken[, callback])**

  Verifies an email address using an email token. Should be used together with the Email Add-on.

  ```javascript
  user.verifyEmail('EMAIL_TOKEN', function(error, result) {});
  ```

* **user.resetPassword(user[, callback])**

  Use this together with the Email Add-on to send a reset-password email to the user.

  ```javascript
  user.resetPassword({ login: 'timothy' }, function(error, result) {});
  ```

* **user.setPassword(passwordToken, newPassword[, callback])**

  Sets a new password using a password token.

  ```javascript
  user.setPassword('PASSWORD_TOKEN', 'secretPassw0rd', function(error, result) {});
  ```

* **user.hasPermission(permissions)**

  Returns `true` if the user has all the permissions in the string or array `permissions`. Else it returns `false`.
  
  ```javascript              
  var result = user.hasPermission('edit');
  var result = user.hasPermission(['edit', 'post']);
  ```

* **user.hasFeature(features)**

  Returns `true` if the user has all the features in the string or array `features`. Else it returns `false`.
  
  ```javascript              
  var result = user.hasFeature('editor');
  var result = user.hasFeature(['editor', 'another_feature']);
  ```

### UserApp

>Exposes the full UserApp API with the [JavaScript library](https://app.userapp.io/#/docs/libs/javascript/).

## Directives

* **ua-login**

  Add this to a form tag to attach it to the `user.login()` function. The `error` object will be set when an error occurs.

  ```html
  <form ua-login>
      <input name="login" placeholder="Username"><br>
      <input name="password" placeholder="Password" type="password"><br>
      <button type="submit">Log In</button>
			
      <p ng-show="error">{{ error.message }}</p>
  </form>
  ```

* **ua-logout**

  Add this to a log out link to attach it to the `user.logout()` function.

  ```html
  <a href="#" ua-logout>Log Out</a>
  ```

* **ua-signup**

  Add this to a form tag to attach it to the `user.signup()` function. Use the `error` object to show an message if an error occurs. Use `ua-is-email` on the login input to specify that login is the same as email. All input field names must reflect the [user's properties](https://app.userapp.io/#/docs/user/#properties).

  ```html
  <form ua-signup>
      <input name="first_name" placeholder="Name"><br>
      <input name="login" ua-is-email placeholder="Email"><br>
      <input name="password" placeholder="Password" type="password"><br>
      <button type="submit">Create Account</button>
			
      <p ng-show="error">{{ error.message }}</p>
  </form>
  ```

  To set custom properties on the user at the signup, name the custom fields `properties.[name]`. For example if you have a property called `age`, create an input like this:

  ```html
  <input name="properties.age" placeholder="Age">
  ```

  **Note:** If you have activated the Email Add-on and the Verification Email, the user won't be logged in after the sign up. Instead, the variable `verificationEmailSent` will be set to `true` so you could display a message to the user asking them to check the inbox.

* **ua-reset-password**

  Add this to a form tag to attach it to the `user.resetPassword()` function. Use the `error` object to show an message if an error occurs. The form must have an input named `login`. When the email has been sent out, the variable `emailSent` will be set to `true`. This directive can only be used together with the Email Add-on to send reset-password email.

  ```html
  <form ua-reset-password ng-show="!emailSent">
      <input name="login" placeholder="Username"><br>
      <button type="submit">Send email</button>

      <p ng-show="error">{{ error.message }}</p>
  </form>
  <p ng-show="emailSent">An email has been sent to your inbox. Click on the link to set a new password.</p>
  ```

* **ua-set-password**

  Add this to a form tag to attach it to the `user.setPassword()` function (i.e. the API method `user.changePassword()` with the parameter `password_token`). Use the `error` object to show an message if an error occurs. The form must have an input named `new_password`. When the password has been saved, the variable `passwordSaved` will be set to `true`.

  ```html
  <form ua-set-password ng-show="!passwordSaved">
      <input name="new_password" type="password" placeholder="New password"><br>
      <button type="submit">Save</button>
    
      <p ng-show="error">{{ error.message }}</p>
  </form>
  <p ng-show="passwordSaved">Your new password has been saved, now <a href="#/login">log in</a>!</p>
  ```

* **ua-oauth-link**

  Add this to a link tag in order to authenticate using an OAuth provider. The value should be an OAuth provider id such as `google`, `github`, `facebook` or `linkedin`. *Additionally:* Use the `error` object to show an message if an error occurs. Use `ua-oauth-scopes` to specify OAuth scopes to request by provider. The scopes must be a comma-separated list of scopes, i.e. `user,user:email`. Use `ua-oauth-redirect-uri` to explicitly specify the URI to be redirected to after provider has performed authentication. If not specified, the default URI will be `/#/oauth/callback/`.

  ```html
  <a href="" ua-oauth-link="google">Log in with Google</a>
  ```

  [Read more about how to use OAuth/*Social Login* with UserApp.](https://app.userapp.io/#/docs/concepts/#social-login)

* **ua-has-permission="permissions"**

  Add this to an element to attach it to the `user.hasPermission()` function. The element will be hidden if not all permissions are true. Multiple permissions are separated with whitespace.

  ```html
  <a href="#" ua-has-permission="edit">Edit Post</a>
  ```

* **ua-has-feature="features"**

  Add this to an element to attach it to the `user.hasFeature()` function. The element will be hidden if not all features are true. Multiple features are separated with whitespace.

  ```html
  <a href="#" ua-has-feature="fancy_feature">Go to Fancy Feature...</a>
  ```

## Events

* **user.error**

  Event triggered when an error occurs.

  ```javascript	
  $rootScope.$on('user.error', function(sender, error) {
      console.log(error.message);
  });
  ```

* **user.login**

  Event triggered when user logs in.

  ```javascript	
  $rootScope.$on('user.login', function() {
      console.log(user.current);
  });
  ```
	
* **user.logout**

  Event triggered when user logs out.

  ```javascript	
  $rootScope.$on('user.logout', function() {
      console.log('Bye!');
  });
  ```

## Example

See [example/](https://github.com/userapp-io/userapp-angular/tree/master/example) for a demo app based on [angular-seed](https://github.com/angular/angular-seed).

## Help

Contact us via email at support@userapp.io or visit our [support center](https://help.userapp.io). You can also see the [UserApp documentation](https://app.userapp.io/#/docs/) for more information.

## License

MIT, see LICENSE.
