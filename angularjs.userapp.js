'use strict';

// Module with AngularJS services and directives that integrates UserApp into your app
// https://github.com/userapp-io/userapp-angular
var userappModule = angular.module('UserApp', []);

(function(){
    // Expose the UserApp API
    userappModule.value('UserApp', UserApp);

    /**
     * Token storage, default is in a cookie. The PhoneGap integration will override this
     * to store the token in localStorage instead.
     */
    UserApp.tokenStorage || (UserApp.tokenStorage = {
        get: function() {
            return Cookies.get('ua_session_token');
        },
        set: function(token) {
            Cookies.set('ua_session_token', token, { expires: new Date(new Date().getTime() + 31536000000) });
        },
        remove: function() {
            Cookies.expire('ua_session_token');
        }
    });

    // Directive error handler
    var handleError = function(scope, error, elementId) {
        if (!error) {
            return;
        }
        
        error.handled = false;

        if (elementId) {
            error.handled = true;
            angular.element(document.getElementById(elementId)).text(error.message);
        }

        scope.$emit('user.error', error);
    };

    // Function to detect if a route is public or not
    var isPublic = function(route) {
        return (route && (route.public == true || route.login == true || route.verify_email == true || route.set_password == true));
    };

    // Authentication service
    userappModule.factory('user', function($rootScope, $location, $injector, $log, $timeout, $q) {
        var user = {};
        var appId = null;
        var options = null;
        var token = UserApp.tokenStorage.get();
        var status = { authorized: false, authenticated: false };
        var heartBeatInterval = -1;
        var defaultRoute = null;
        var loginRoute = null;
        var states = {};

        // Check if either ng-route or ui-router is present
        if ($injector.has) {
            var $route = $injector.has('$route') ? $injector.get('$route') : null;
            var $state = $injector.has('$state') ? $injector.get('$state') : null;
        } else {
            var $route = $injector.get('$route');
            var $state = null;
        }

        if ($state && (!$state.transitionTo || !$state.get)) {
            // This is not the correct $state service
            $state = null;
        }
        
        if (!$state && !$route) {
            $log.warn('The UserApp module needs either ng-route or ui-router to work as expected.');
        }

        if ($state) {
            // Get the list of all states
            var stateList = $state.get();
            for (var i = 0; i < stateList.length; ++i) {
                states[stateList[i].name] = stateList[i];
            }
        }

        var transitionTo = function(state, useLocation) {
            if ($state) {
                if (useLocation) {
                    $location.path(states[state].url);
                } else {
                    $state.transitionTo(state);
                }
            } else if ($route) {
                $location.path(state);
            }
        };

        // Controller for the verify email route
        var verifyEmailController = function($scope, $location, $timeout) {
            $scope.loading = true;
            
            var emailToken = $location.search().email_token;
            service.verifyEmail(emailToken, function(error, result) {
                if (error) {
                    $timeout(function() {
                        $scope.error = error;
                    });
                } else {
                    $timeout(function() {
                        $scope.loading = false;
                    });
                }
            });
        };

        /**
         * Invokes authenticationRequired/accessDeniedHandler if state is protected.
         * Returns false if access should be denied.
         */
        var checkAccessToState = function(state, stateParams) {
            if (state) {
                if ((!state.data || (state.data && isPublic(state.data) == false)) && status.authenticated == false) {
                    service.authenticationRequiredHandler(state, stateParams);
                    return false;
                } else if (state.data && state.data.hasPermission && user.permissions) {
                    if (!service.hasPermission(state.data.hasPermission)) {
                        service.accessDeniedHandler(user, state, stateParams);
                        return false;
                    }
                }
                // Only do auth check if user is loaded (indicated by user_id present)
                else if (state.data && state.data.authCheck && user.user_id) {
                    if (!state.data.authCheck(user, stateParams)) {
                        service.accessDeniedHandler(user, state, stateParams);
                        return false;
                    }
                }
            }
            return true;
        };

        /**
         * Invokes authenticationRequired/accessDeniedHandler if route is protected. 
         * Returns false if access should be denied.
         */
        var checkAccessToRoute = function(route) {
            if (route.$$route) {
                if (isPublic(route.$$route) == false && status.authenticated == false) {
                    service.authenticationRequiredHandler(route);
                    return false;
                } else if (route.$$route.hasPermission && user.permissions && !service.hasPermission(route.$$route.hasPermission)) {
                    service.accessDeniedHandler(user, route);
                    return false;
                } else if (route.$$route.authCheck && status.authenticated && !route.$$route.authCheck(user)) {
                    service.accessDeniedHandler(user, route);
                    return false;
                }
            }
            return true;
        };

        // Expose the user object to HTML templates via the root scope
        $rootScope.user = user;
        $rootScope.user.authorized = false;
        $rootScope.user.authenticated = false;

        // The service
        var service = {
            authenticationRequiredHandler: function() {
                $timeout(function() {
                    transitionTo(loginRoute);
                });
            },
            accessDeniedHandler: function() {
                $timeout(function () {
                    transitionTo(defaultRoute, true);
                });
            },
            authenticationSuccessHandler: function() {
                $timeout(function() {
                    transitionTo(defaultRoute, true);
                });
            },

            /**
             * Overwrites the default handler that is invoked if a route/state is activated that requires authentication
             * but no user is logged in. If the Angular router is used, the handler is passed the route that requires
             * authentication. If UI router is used, the handler is passed the state that requires authentication, and
             * its state parameters.
             */
            onAuthenticationRequired: function(handler) {
                this.authenticationRequiredHandler = handler;
            },

            /**
             * Overwrites the default handler that is invoked if a user authenticates successfully.
             */
            onAuthenticationSuccess: function(handler) {
                this.authenticationSuccessHandler = handler;
            },

            /**
             * Overwrites the default handler that is invoked if a route/state is activated that the currently logged in
             * user has no access to. Access is denied if the user does not have a required permission or authCheck
             * returns false.
             * The currently logged in user is the first parameter passed to the handler.
             * If the Angular router is used, the handler is passed the route that access was denied to. If UI router is
             * used, the handler is passed the state that access was denied to, and its state parameters.
             */
            onAccessDenied: function(handler) {
                this.accessDeniedHandler = handler;
            },

            // Initialize the service
            init: function(config) {
                var that = this;
                var authResolver = {
                    auth: function($q, user) {
                        if ($state) {
                            var state = states[this.self.name];
                        }
                        
                        if (isPublic($route ? $route.current.$$route : state) == false) {
                            var deferred = $q.defer();

                            try {
                                user.getCurrent().then(function() {
                                    if ($route ? checkAccessToRoute($route.current) : checkAccessToState(state)) {
                                        deferred.resolve();
                                    } else {
                                        deferred.reject();
                                    }
                                }, function() {
                                    deferred.reject();
                                });
                            } catch(e) {
                                deferred.reject(e);
                            }

                            return deferred.promise;
                        } else {
                            return true;
                        }
                    }
                };
                options = config;

                if ($state) {
                    // Set the default state
                    defaultRoute = '';

                    for (var state in states) {
                        // Add resolver for user and permissions
                        states[state].resolve = (states[state].resolve || {});
                        angular.extend(states[state].resolve, authResolver);

                        // Found the login state
                        if (states[state].data && states[state].data.login) {
                            loginRoute = state;
                        }
                    }
                } else if ($route) {
                    // Find the default route
                    defaultRoute = ($route.routes.null || { redirectTo: '' }).redirectTo;

                    for (var route in $route.routes) {
                        // Add resolver for user and permissions
                        $route.routes[route].resolve = ($route.routes[route].resolve || {});
                        angular.extend($route.routes[route].resolve, authResolver);

                        // Found the login route
                        if ($route.routes[route].login) {
                            loginRoute = $route.routes[route].originalPath;
                        }
                    }
                }

                // Initialize UserApp
                UserApp.initialize({});

                // App Id
                this.appId(config.appId);

                // If a UserApp token is present, use that for authentication
                var remoteToken;
                if (!token && (remoteToken = $location.search().ua_token)) {
                    this.activate(remoteToken, function() {
                        if (UserApp.setupPersistentToken) {
                            UserApp.setupPersistentToken(function(error, token) {
                                if (token) {
                                    that.token(token.value);
                                }
                            });
                        }
                    });
                } else if (token) {
                    this.activate(token);
                }

                // Listen for route changes
                if ($state) {
                    $rootScope.$on('$stateChangeStart', function(ev, toState, toParams) {
                        // Check if this is the verify email route
                        if (toState.data && toState.data.verify_email == true) {
                            toState.controller = verifyEmailController;
                            
                            if (toState.views && toState.views['']) {
                                toState.views[''].controller = verifyEmailController;
                            }
                            
                            return;
                        }

                        if (!checkAccessToState(toState, toParams)) {
                            ev.preventDefault();
                        }
                    });
                } else if ($route) {
                    $rootScope.$on('$routeChangeStart', function(ev, data) {
                        // Check if this is the verify email route
                        if (data.$$route && data.$$route.verify_email == true) {
                            data.$$route.controller = verifyEmailController;
                            return;
                        }

                        if (!checkAccessToRoute(data)) {
                            ev.preventDefault();
                        }
                    });
                }
            },

            // The logged in user
            current: user,

            // Status of current session
            status: function() {
                return status;
            },

            // Reset session
            reset: function() {
                clearInterval(heartBeatInterval);

                UserApp.setToken(null);
                token = null;
                status.authorized = false;
                status.authenticated = false;

                // Remove session cookie
                UserApp.tokenStorage.remove();

                for (var key in user) {
                    delete user[key];
                }

                // Check access to the current route/state again, now that session is reset
                if ($state) {
                    checkAccessToState($state.current, $state.params);
                } else if ($route) {
                    checkAccessToRoute($route.current);
                }
            },

            // Get and set app id
            appId: function(value) {
                if (value) {
                    appId = value;
                    UserApp.setAppId(appId);
                }
                
                return appId;
            },

            // Get and set session token
            token: function(value) {
                if (value) {
                    token = value;

                    UserApp.setToken(token);
                    status.authorized = true;
                    status.authenticated = true;
                    $rootScope.user.authorized = true;
                    $rootScope.user.authenticated = true;

                    // Set session cookie
                    UserApp.tokenStorage.set(token);
                }
                
                return token;
            },

            // Activate the session (set token, load user, start heartbeat, trigger event)
            activate: function(token, callback) {
                var that = this;
                this.token(token);
                this.startHeartbeat(options.heartbeatInterval);

                // Load the logged in user
                this.loadUser(function(error, result) {
                    if (!error) {
                        callback && callback(error, result);

                        // Check access to the current route/state again, now that session is activated
                        if ($state) {
                            checkAccessToState($state.current, $state.params);
                        } else if ($route) {
                            checkAccessToRoute($route.current);
                        }

                        $rootScope.$broadcast('user.login');
                    } else {
                        that.reset();
                    }
                });
            },

            // Sign up a new user and logs in
            signup: function(user, callback) {
                var that = this;
                this.reset();

                if (!user.password) {
                    callback && callback({ name: 'MISSING_PASSWORD', message: "Please enter a password." }, null);
                    return;
                }

                UserApp.User.save(user, function(error, result) {
                    if (!error) {
                        // Check locks
                        if (result.locks && result.locks.length > 0 && result.locks[0].type == 'EMAIL_NOT_VERIFIED') {
                            callback && callback({ name: 'EMAIL_NOT_VERIFIED' }, result);
                            return;
                        } else {
                            // Success - Log in the user
                            that.login(user);
                        }
                    }

                    callback && callback(error, result);
                });
            },

            // Verify email address with a token
            verifyEmail: function(emailToken, callback) {
                if (emailToken) {
                    UserApp.User.verifyEmail({ email_token: emailToken }, function(error, result) {
                        callback && callback(error, result);
                    });
                } else {
                    callback && callback({ name: 'INVALID_ARGUMENT_EMAIL_TOKEN', message: 'Missing email verification token.' }, null);
                }
            },

            // Start new session / Login user
            login: function(user, callback) {
                var that = this;
                this.reset();

                UserApp.User.login(user, function(error, result) {
                    if (result) {
                        if (result.locks && result.locks.indexOf('EMAIL_NOT_VERIFIED') > -1) {
                            UserApp.setToken(null);
                            callback && callback({ name: 'EMAIL_NOT_VERIFIED', message: 'Please verify your email address by clicking on the link in the verification email that we\'ve sent you.' }, result);
                        } else if (result.locks && result.locks.length > 0) {
                            UserApp.setToken(null);
                            callback && callback({ name: 'LOCKED', message: 'Your account has been locked.' }, result);
                        } else {
                            that.activate(result.token, function() {
                                if (UserApp.setupPersistentToken) {
                                    UserApp.setupPersistentToken(function(error, token) {
                                        if (token) {
                                            that.token(token.value);
                                        }
                                        callback && callback(error, result);
                                    });
                                } else {
                                    callback && callback(error, result);
                                }

                                // Invoke the authenticationSuccessHandler handler
                                that.authenticationSuccessHandler();
                            });
                        }
                    } else {
                        callback && callback(error, result);
                    }
                });
            },

            // End session / Logout user
            logout: function(callback) {
                var that = this;

                if (UserApp.removePersistentToken) {
                    UserApp.removePersistentToken(function(error) {
                        that.reset();
                        $rootScope.$broadcast('user.logout');
                        callback && callback(error);
                    });
                } else {
                    UserApp.User.logout(function(error) {
                        that.reset();
                        $rootScope.$broadcast('user.logout');
                        callback && callback(error);
                    });  
                }
            },

            // Send reset password email
            resetPassword: function(user, callback) {
                var that = this;
                this.reset();

                UserApp.User.resetPassword(user, function(error, result) {
                    callback && callback(error, result);
                });
            },

            // Set new password
            setPassword: function(passwordToken, newPassword, callback) {
                var that = this;
                this.reset();

                UserApp.User.changePassword({ password_token: passwordToken, new_password: newPassword }, function(error, result) {
                    callback && callback(error, result);
                });
            },

            // Check if the user has permission
            hasPermission: function(permissions) {
                if (!this.current || !this.current.permissions || !permissions) {
                    return false;
                }

                if (typeof(permissions) != 'object') {
                    permissions = [permissions];
                }

                for (var i = 0; i < permissions.length; ++i) {
                    if (!(this.current.permissions[permissions[i]] && this.current.permissions[permissions[i]].value === true)) {
                        return false;
                    }
                }

                return true;
            },

            // Check if the user has features
            hasFeature: function(features) {
                if (!this.current || !this.current.features || !features) {
                    return false;
                }

                if (typeof(features) != 'object') {
                    features = [features];
                }

                for (var i = 0; i < features.length; ++i) {
                    if (!(this.current.features[features[i]] && this.current.features[features[i]].value === true)) {
                        return false;
                    }
                }

                return true;
            },

            // Load the logged in user
            loadUser: function(callback) {
                var that = this;

                UserApp.User.get({ user_id: 'self' }, function(error, result) {
                    if (!error) {
                        $timeout(function() {
                            angular.extend(user, result[0]);
                            callback && callback(error, result);
                        });
                    } else {
                        callback && callback(error, result);
                    }
                });
            },

            // Load the logged in user with a promise
            getCurrent: function() {
                var deferred = $q.defer();
                var that = this;

                try {
                    if (this.current.user_id) {
                        deferred.resolve(this.current);
                    } else {
                        var turnOff = $rootScope.$on('user.login', function () {
                            deferred.resolve(that.current);
                            turnOff();
                        });
                    }
                } catch(e) {
                    deferred.reject(e);
                }

                return deferred.promise;
            },

            // Start session heartbeat
            startHeartbeat: function(interval) {
                var that = this;

                if (interval != undefined && interval < 10000) {
                    return;
                }

                clearInterval(heartBeatInterval);
                heartBeatInterval = setInterval(function() {
                    UserApp.Token.heartbeat(function(error, result) {
                        if (error) {
                            that.reset();
                            $rootScope.$broadcast('user.logout');
                        } else {
                            status.authorized = result.alive;
                            status.authenticated = result.alive;
                        }
                    });
                }, interval || 20000);
            }
        };

        // Extend the current user with hasPermission() and hasFeature()
        angular.extend(user, { 
            hasPermission: function(permissions) {
                return service.hasPermission(permissions);
            }, 
            hasFeature: function(features) {
                return service.hasFeature(features);
            }
        });

        return service;
    });

    // Logout directive
    userappModule.directive('uaLogout', function($timeout, user) {
        return {
            restrict: 'A',
            link: function(scope, element, attrs) {
                var evHandler = function(e) {
                    e.preventDefault();
                    
                    if (scope.loading) {
                        return false;
                    }
                    
                    $timeout(function() {
                        scope.loading = true;
                    });
                    
                    user.logout(function() {
                        $timeout(function() {
                            scope.loading = false;
                        });
                    });
                    
                    return false;
                };

                element.on ? element.on('click', evHandler) : element.bind('click', evHandler);
            }
        };
    });

    // Login directive
    userappModule.directive('uaLogin', function($rootScope, $timeout, user) {
        return {
            restrict: 'A',
            link: function(scope, element, attrs) {
                var evHandler = function(e) {
                    e.preventDefault();

                    if (scope.loading) {
                        return false;
                    }

                    $timeout(function() {
                        scope.error = null;
                        scope.loading = true;
                    });

                    user.login({ login: this.login.value, password: this.password.value }, function(error, result) {
                        if (error) {
                            $timeout(function() {
                                scope.error = error;
                                scope.loading = false;
                            });
                            return handleError(scope, error, attrs.uaError);
                        } else {
                            $timeout(function() {
                                scope.loading = false;
                            });
                        }
                    });

                    return false;
                };

                element.on ? element.on('submit', evHandler) : element.bind('submit', evHandler);
            }
        };
    });

    // Signup directive
    userappModule.directive('uaSignup', function($rootScope, $timeout, user, UserApp) {
        return {
            restrict: 'A',
            link: function(scope, element, attrs) {
                var evHandler = function(e) {
                    e.preventDefault();

                    if (scope.loading) {
                        return false;
                    }

                    $timeout(function() {
                        scope.error = null;
                        scope.verificationEmailSent = false;
                        scope.loading = true;
                    });

                    // Create the sign up object
                    var object = {};
                    for (var i = 0; i < this.elements.length; ++i) {
                        if (this.elements[i].name) {
                            var scopes = this.elements[i].name.split('.');
                            if (scopes.length > 1) {
                                object[scopes[0]] = object[scopes[0]] || {};
                                object[scopes[0]][scopes[1]] = this.elements[i].value;
                            } else {
                                object[this.elements[i].name] = this.elements[i].value;
                            }

                            if (angular.element(this.elements[i]).attr('ua-is-email') != undefined) {
                                object['email'] = this.elements[i].value;
                            }
                        }
                    }
                    
                    // Sign up
                    user.signup(object, function(error, result) {
                        if (error) {
                            if (error) {
                                if (error.name != 'EMAIL_NOT_VERIFIED') {
                                    $timeout(function() {
                                        scope.error = error;
                                        scope.loading = false;
                                    });
                                    return handleError(scope, error, attrs.uaError);
                                } else {
                                    $timeout(function() {
                                        scope.verificationEmailSent = true;
                                        scope.loading = false;
                                    });
                                }
                            }
                        }
                    });

                    return false;
                };

                element.on ? element.on('submit', evHandler) : element.bind('submit', evHandler);
            }
        };
    });
    
    // Reset password directive
    userappModule.directive('uaResetPassword', function($rootScope, $timeout, user) {
        return {
            restrict: 'A',
            link: function(scope, element, attrs) {
                var evHandler = function(e) {
                    e.preventDefault();

                    if (scope.loading) {
                        return false;
                    }

                    $timeout(function() {
                        scope.error = null;
                        scope.loading = true;
                    });

                    user.resetPassword({ login: this.login.value }, function(error, result) {
                        if (error) {
                            $timeout(function() {
                                scope.error = error;
                                scope.loading = false;
                            });
                            return handleError(scope, error, attrs.uaError);
                        } else {
                            $timeout(function() {
                                scope.emailSent = true;
                                scope.loading = false;
                            });
                        }
                    });

                    return false;
                };

                element.on ? element.on('submit', evHandler) : element.bind('submit', evHandler);
            }
        };
    });

    // Set password directive
    userappModule.directive('uaSetPassword', function($rootScope, $location, $timeout, user) {
        return {
            restrict: 'A',
            link: function(scope, element, attrs) {
                var evHandler = function(e) {
                    e.preventDefault();

                    if (scope.loading) {
                        return false;
                    }

                    $timeout(function() {
                        scope.error = null;
                        scope.loading = true;
                    });

                    user.setPassword($location.search().password_token, this.new_password.value, function(error, result) {
                        if (error) {
                            $timeout(function() {
                                scope.error = error;
                                scope.loading = false;
                            });
                            return handleError(scope, error, attrs.uaError);
                        } else {
                            $timeout(function() {
                                scope.passwordSaved = true;
                                scope.loading = false;
                            });
                        }
                    });

                    return false;
                };

                element.on ? element.on('submit', evHandler) : element.bind('submit', evHandler);
            }
        };
    });

    // OAuth URL directive
    userappModule.directive('uaOauthLink', function($timeout, $location, user, UserApp) {
        return {
            restrict: 'A',
            link: function(scope, element, attrs) {
                var evHandler = function(e) {
                    e.preventDefault();

                    if (scope.loading) {
                        return false;
                    }

                    $timeout(function() {
                        scope.error = null;
                        scope.loading = true;
                    });

                    function getHashMode() {
                        var hash = $location.absUrl().replace(window.location.protocol+'//'+window.location.host+window.location.pathname, '');
                        return hash.replace($location.path(), '');
                    };

                    var providerId = attrs.uaOauthLink;
                    var scopes = 'uaOauthScopes' in attrs ? (attrs.uaOauthScopes || '').split(',') : null;
                    var defaultRedirectUrl = window.location.protocol+'//'+window.location.host+window.location.pathname+getHashMode()+'/oauth/callback/';
                    var redirectUri = 'uaOauthRedirectUri' in attrs ? attrs.uaOauthRedirectUri : defaultRedirectUrl;
                    
                    // PhoneGap/iOS fix
                    if (window.device && window.device.platform == 'iOS') {
                        if (redirectUri.indexOf('file://') == 0) {
                            redirectUri = 'https://oauth.userapp.io/';
                        }
                    }

                    UserApp.OAuth.getAuthorizationUrl({ provider_id: providerId, redirect_uri: redirectUri, scopes: scopes }, function(error, result) {
                        if (error) {
                            $timeout(function() {
                                scope.error = error;
                                scope.loading = false;
                            });
                            return handleError(scope, error, attrs.uaError);
                        } else {
                            if (UserApp.oauthHandler) {
                                UserApp.oauthHandler(result.authorization_url, function(token) {
                                    if (token) {
                                        user.activate(token, function() {
                                            user.authenticationSuccessHandler();
                                        });
                                    } else {
                                        $timeout(function() {
                                            scope.loading = false;
                                        });
                                    }
                                });
                            } else {
                                window.location.href = result.authorization_url;
                            }
                        }
                    });

                    return false;
                };

                element.on ? element.on('click', evHandler) : element.bind('click', evHandler);
            }
        };
    });

    // hasPermission directive
    userappModule.directive('uaHasPermission', function(user) {
        return {
            restrict: 'A',
            link: function(scope, element, attrs) {
                var display = element.css('display');
                element.css('display', 'none');

                scope.user = user.current;
                var permissions = attrs.uaHasPermission.split(' ');

                if (permissions) {
                    scope.$watch('user', function() {
                        if (user.hasPermission(permissions)) {
                            element.css('display', display);
                        } else {
                            element.css('display', 'none');
                        }
                    }, true);
                }
            }
        };
    });

    // hasFeature directive
    userappModule.directive('uaHasFeature', function(user) {
        return {
            restrict: 'A',
            link: function(scope, element, attrs) {
                var display = element.css('display');
                element.css('display', 'none');

                scope.user = user.current;
                var features = attrs.uaHasFeature.split(' ');

                if (features) {
                    scope.$watch('user', function() {
                        if (user.hasFeature(features)) {
                            element.css('display', display);
                        } else {
                            element.css('display', 'none');
                        }
                    }, true);
                }
            }
        };
    });

    /*! Cookies.js - 0.3.1; Copyright (c) 2013, Scott Hamper; http://www.opensource.org/licenses/MIT */
    (function(e){"use strict";var a=function(b,d,c){return 1===arguments.length?a.get(b):a.set(b,d,c)};a._document=document;a._navigator=navigator;a.defaults={path:"/"};a.get=function(b){a._cachedDocumentCookie!==a._document.cookie&&a._renewCache();return a._cache[b]};a.set=function(b,d,c){c=a._getExtendedOptions(c);c.expires=a._getExpiresDate(d===e?-1:c.expires);a._document.cookie=a._generateCookieString(b,d,c);return a};a.expire=function(b,d){return a.set(b,e,d)};a._getExtendedOptions=function(b){return{path:b&& b.path||a.defaults.path,domain:b&&b.domain||a.defaults.domain,expires:b&&b.expires||a.defaults.expires,secure:b&&b.secure!==e?b.secure:a.defaults.secure}};a._isValidDate=function(b){return"[object Date]"===Object.prototype.toString.call(b)&&!isNaN(b.getTime())};a._getExpiresDate=function(b,d){d=d||new Date;switch(typeof b){case "number":b=new Date(d.getTime()+1E3*b);break;case "string":b=new Date(b)}if(b&&!a._isValidDate(b))throw Error("`expires` parameter cannot be converted to a valid Date instance"); return b};a._generateCookieString=function(b,a,c){b=encodeURIComponent(b);a=(a+"").replace(/[^!#$&-+\--:<-\[\]-~]/g,encodeURIComponent);c=c||{};b=b+"="+a+(c.path?";path="+c.path:"");b+=c.domain?";domain="+c.domain:"";b+=c.expires?";expires="+c.expires.toUTCString():"";return b+=c.secure?";secure":""};a._getCookieObjectFromString=function(b){var d={};b=b?b.split("; "):[];for(var c=0;c<b.length;c++){var f=a._getKeyValuePairFromCookieString(b[c]);d[f.key]===e&&(d[f.key]=f.value)}return d};a._getKeyValuePairFromCookieString= function(b){var a=b.indexOf("="),a=0>a?b.length:a;return{key:decodeURIComponent(b.substr(0,a)),value:decodeURIComponent(b.substr(a+1))}};a._renewCache=function(){a._cache=a._getCookieObjectFromString(a._document.cookie);a._cachedDocumentCookie=a._document.cookie};a._areEnabled=function(){var b="1"===a.set("cookies.js",1).get("cookies.js");a.expire("cookies.js");return b};a.enabled=a._areEnabled();"function"===typeof define&&define.amd?define(function(){return a}):"undefined"!==typeof exports?("undefined"!== typeof module&&module.exports&&(exports=module.exports=a),exports.Cookies=a):window.Cookies=a})();
})();
