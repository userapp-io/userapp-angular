'use strict';

(function(){
    // Module with AngularJS services and directives that integrates UserApp into your app
    // https://github.com/userapp-io/userapp-angular
    var userappModule = angular.module('UserApp', []);

    // Expose the UserApp API
    userappModule.value('UserApp', UserApp);

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

    // Safe scope apply
    var safeApply = function(scope, fn) {
        var phase = scope.$root.$$phase;
        if (phase == '$apply' || phase == '$digest') {
            if (fn && (typeof (fn) === 'function')) {
                fn();
            }
        } else {
            scope.$apply(fn);
        }
    };

    // Function to detect if a route is public or not
    var isPublic = function(route) {
        return (route.public == true || route.login == true || route.verify_email == true || route.set_password == true);
    };

    // Authentication service
    userappModule.factory('user', function($rootScope, $location, $injector, $log) {
        var user = {};
        var appId = null;
        var token = Kaka.get('ua_session_token');
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
        var verifyEmailController = function($scope, $location) {
            $scope.loading = true;
            
            var emailToken = $location.search().email_token;
            service.verifyEmail(emailToken, function(error, result) {
                if (error) {
                    safeApply($scope, function() {
                        $scope.error = error;
                    });
                } else {
                    safeApply($scope, function() {
                        $scope.loading = false;
                    });
                }
            });
        };

        // Expose the user object to HTML templates via the root scope
        $rootScope.user = user;
        $rootScope.user.authorized = false;
        $rootScope.user.authenticated = false;

        // The service
        var service = {
            // Initialize the service
            init: function(config) {
                var that = this;

                if ($state) {
                    // Set the default state
                    defaultRoute = '';

                    // Find the login state
                    for (var state in states) {
                        if (states[state].data && states[state].data.login) {
                            loginRoute = state;
                            break;
                        }
                    }
                } else if ($route) {
                    // Find the default route
                    defaultRoute = ($route.routes.null || { redirectTo: '' }).redirectTo;

                    // Find the login route
                    for (var route in $route.routes) {
                        if ($route.routes[route].login) {
                            loginRoute = $route.routes[route].originalPath;
                            break;
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
                    token = remoteToken;
                }

                token && this.activate(token);

                // Listen for route changes
                if ($state) {
                    $rootScope.$on('$stateChangeStart', function(ev, toState) {
                        // Check if this is the verify email route
                        if (!toState.data || (toState.data && toState.data.verify_email == true)) {
                            toState.controller = verifyEmailController;
                            return;
                        }

                        // Check if this state is protected
                        if ((!toState.data || (toState.data && isPublic(toState.data) == false)) && status.authenticated == false) {
                            ev.preventDefault();
                            safeApply($rootScope, function() {
                                // Redirect to login route
                                transitionTo(loginRoute);
                            });
                        } else if ((!toState.data || (toState.data && toState.data.hasPermission)) && that.current.permissions) {
                            if (!that.hasPermission(toState.data.hasPermission)) { 
                                safeApply($rootScope, function() {
                                    transitionTo(defaultRoute, true);
                                });
                            }
                        }
                    });
                } else if ($route) {
                    $rootScope.$on('$routeChangeStart', function(ev, data) {
                        // Check if this is the verify email route
                        if (data.$$route && data.$$route.verify_email == true) {
                            data.$$route.controller = verifyEmailController;
                            return;
                        }

                        // Check if this route is protected
                        if (data.$$route && isPublic(data.$$route) == false && status.authenticated == false) {
                            ev.preventDefault();
                            safeApply($rootScope, function() {
                                // Redirect to login route
                                transitionTo(loginRoute);
                            });
                        } else if (data.$$route && data.$$route.hasPermission && that.current.permissions) {
                            if (!that.hasPermission(data.$$route.hasPermission)) { 
                                safeApply($rootScope, function() {
                                    transitionTo(defaultRoute);
                                });
                            }
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
                Kaka.remove('ua_session_token');

                for (var key in user) {
                    delete user[key];
                }

                // Redirect to login route
                if ($state) {
                    if ($state.$current && (!$state.$current.data || isPublic($state.$current.data) == false)) {
                        safeApply($rootScope, function() {
                            transitionTo(loginRoute, true);
                        });
                    }
                } else if ($route) {
                    if ($route.current && isPublic($route.current.$$route) == false) {
                        safeApply($rootScope, function() {
                            transitionTo(loginRoute);
                        });
                    }
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
                    Kaka.set('ua_session_token', token);
                }
                
                return token;
            },

            // Activate the session (set token, load user, start heartbeat, trigger event)
            activate: function(token, callback) {
                var that = this;
                this.token(token);
                this.startHeartbeat();

                // Redirect to default route
                if ($state) {
                    if ($state.$current && $state.$current.data && isPublic($state.$current.data)) {
                        safeApply($rootScope, function() {
                            transitionTo(defaultRoute, true);
                        });
                    }
                } else if ($route) {
                    if ($route.current && isPublic($route.current.$$route)) {
                        safeApply($rootScope, function() {
                            transitionTo(defaultRoute);
                        });
                    }
                }

                // Load the logged in user
                this.loadUser(function(error, result) {
                    callback && callback(error, result);
                    $rootScope.$broadcast('user.login');

                    // Check permissions for this route
                    if ($state) {
                        if ($state.$current && $state.$current.data && $state.$current.data.hasPermission) {
                            if (!that.hasPermission($state.$current.data.hasPermission)) { 
                                safeApply($rootScope, function() {
                                    transitionTo(defaultRoute, true);
                                });
                            }
                        }
                    } else if ($route) {
                        if ($route.current && $route.current.$$route.hasPermission) {
                            if (!that.hasPermission($route.current.$$route.hasPermission)) { 
                                safeApply($rootScope, function() {
                                    transitionTo(defaultRoute);
                                });
                            }
                        }
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
                        // check lock
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
                                callback && callback(error, result);
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

                UserApp.User.logout(function(error) {});

                that.reset();
                $rootScope.$broadcast('user.logout');

                callback && callback(error);
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
                        safeApply($rootScope, function() {
                            angular.extend(user, result[0]);
                            callback && callback(error, result);
                        });
                    } else {
                        callback && callback(error, result);
                    }
                });
            },

            // Start session heartbeat
            startHeartbeat: function(interval) {
                var that = this;

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
    userappModule.directive('uaLogout', function(user) {
        return {
            restrict: 'A',
            link: function(scope, element, attrs) {
                var evHandler = function(e) {
                    e.preventDefault();
                    user.logout();
                    return false;
                };

                element.on ? element.on('click', evHandler) : element.bind('click', evHandler);
            }
        };
    });

    // Login directive
    userappModule.directive('uaLogin', function($rootScope, user) {
        return {
            restrict: 'A',
            link: function(scope, element, attrs) {
                var evHandler = function(e) {
                    e.preventDefault();

                    if (scope.loading) {
                        return false;
                    }

                    safeApply(scope, function() {
                        scope.error = null;
                        scope.loading = true;
                    });

                    user.login({ login: this.login.value, password: this.password.value }, function(error, result) {
                        if (error) {
                            safeApply(scope, function() {
                                scope.error = error;
                                scope.loading = false;
                            });
                            return handleError(scope, error, attrs.uaError);
                        } else {
                            safeApply(scope, function() {
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
    userappModule.directive('uaSignup', function($rootScope, user, UserApp) {
        return {
            restrict: 'A',
            link: function(scope, element, attrs) {
                var evHandler = function(e) {
                    e.preventDefault();

                    if (scope.loading) {
                        return false;
                    }

                    safeApply(scope, function() {
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
                                    safeApply(scope, function() {
                                        scope.error = error;
                                        scope.loading = false;
                                    });
                                    return handleError(scope, error, attrs.uaError);
                                } else {
                                    safeApply(scope, function() {
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
    userappModule.directive('uaResetPassword', function($rootScope, user) {
        return {
            restrict: 'A',
            link: function(scope, element, attrs) {
                var evHandler = function(e) {
                    e.preventDefault();

                    if (scope.loading) {
                        return false;
                    }

                    safeApply(scope, function() {
                        scope.error = null;
                        scope.loading = true;
                    });

                    user.resetPassword({ login: this.login.value }, function(error, result) {
                        if (error) {
                            safeApply(scope, function() {
                                scope.error = error;
                                scope.loading = false;
                            });
                            return handleError(scope, error, attrs.uaError);
                        } else {
                            safeApply(scope, function() {
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
    userappModule.directive('uaSetPassword', function($rootScope, $location, user) {
        return {
            restrict: 'A',
            link: function(scope, element, attrs) {
                var evHandler = function(e) {
                    e.preventDefault();

                    if (scope.loading) {
                        return false;
                    }

                    safeApply(scope, function() {
                        scope.error = null;
                        scope.loading = true;
                    });

                    user.setPassword($location.search().password_token, this.new_password.value, function(error, result) {
                        if (error) {
                            safeApply(scope, function() {
                                scope.error = error;
                                scope.loading = false;
                            });
                            return handleError(scope, error, attrs.uaError);
                        } else {
                            safeApply(scope, function() {
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
    userappModule.directive('uaOauthLink', function(UserApp) {
        return {
            restrict: 'A',
            link: function(scope, element, attrs) {
                var evHandler = function(e) {
                    e.preventDefault();

                    if (scope.loading) {
                        return false;
                    }

                    safeApply(scope, function() {
                        scope.error = null;
                        scope.loading = true;
                    });

                    var providerId = attrs.uaOauthLink;
                    var scopes = 'uaOauthScopes' in attrs ? (attrs.uaOauthScopes || '').split(',') : null;
                    var defaultRedirectUrl = window.location.protocol+'//'+window.location.host+window.location.pathname+'#/oauth/callback/';
                    var redirectUri = 'uaOauthRedirectUri' in attrs ? attrs.uaOauthRedirectUri : defaultRedirectUrl;
                    
                    UserApp.OAuth.getAuthorizationUrl({ provider_id: providerId, redirect_uri: redirectUri, scopes: scopes }, function(error, result){
                        if (error) {
                            safeApply(scope, function() {
                                scope.error = error;
                                scope.loading = false;
                            });
                            return handleError(scope, error, attrs.uaError);
                        }else{
                            window.location.href = result.authorization_url;
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
                element[0].style.display = 'none';

                scope.user = user.current;
                var permissions = attrs.uaHasPermission.split(' ');

                if (permissions) {
                    scope.$watch('user', function() {
                        if (user.hasPermission(permissions)) {
                            element[0].style.display = null;
                        } else {
                            element[0].style.display = 'none';
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
                element[0].style.display = 'none';

                scope.user = user.current;
                var features = attrs.uaHasFeature.split(' ');

                if (features) {
                    scope.$watch('user', function() {
                        if (user.hasFeature(features)) {
                            element[0].style.display = null;
                        } else {
                            element[0].style.display = 'none';
                        }
                    }, true);
                }
            }
        };
    });


    // Kaka - The Embeddable Cookie Library

    // Kaka was created for a purpose, and one purpose only. To add simple cookie support for libraries that need it!
    // It does this with a simple unrestricted license. So change the code, the name (please!), and use it however you like!!

    // https://github.com/comfirm/Kaka.js

    var Kaka = window.Kaka = {};

    Kaka.get = function(name){
            var cookies = {};
            var decodeComponent = decodeURIComponent;
            var data = (document.cookie || "").split("; ");

            for(var i=0;i<data.length;++i){
                    var segments = data[i].split("=", 2);
                    if(segments.length == 2){
                            cookies[decodeComponent(segments[0])] = decodeComponent(segments[1]);
                    }
            }

            return (name === undefined ? cookies : (name in cookies ? cookies[name] : null));
    };

    Kaka.set = function(name, value, expires, path){
            var variables = {};
            var encodeComponent = encodeURIComponent;

            variables[name] = value == undefined || value == null ? '' : value;
            variables['path'] = path || '/';

            if(expires && expires.toGMTString){
                    variables["expires"] = expires.toGMTString();
            }

            var cookie = "";

            for(var key in variables){
                    cookie += (cookie != "" ? "; " : "") + encodeComponent(key) + "=" + encodeComponent(variables[key]);
            }

            document.cookie = cookie;
    };

    Kaka.remove = function(name){
            Kaka.set(name, null, new Date(0));
    };
})();