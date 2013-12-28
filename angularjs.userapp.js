'use strict';

(function(){
    // Module with AngularJS services and directives that integrates UserApp into your app
    // https://github.com/userapp-io/userapp-angular
    var userappModule = angular.module('UserApp', []);

    // Expose the UserApp API
    userappModule.value('UserApp', UserApp);

    // Directive error handler
    var handleError = function(scope, error, elementId){
        if(!error){
            return;
        }
        
        error.handled = false;

        if(elementId){
            error.handled = true;
            angular.element(document.getElementById(elementId)).text(error.message);
        }

        scope.$emit('user.error', error);
    };

    // Authentication service
    userappModule.factory('user', function($rootScope, $route, $location) {
    	var user = {};
    	var appId = null;
        var token = Kaka.get('ua_session_token');
        var status = { authorized: false };
        var heartBeatInterval = -1;
        var defaultRoute = $route.routes.null.redirectTo;
        var loginRoute = null;

        // Expose the user object to HTML templates via the root scope
        $rootScope.user = user;
        $rootScope.user.authorized = false;

        // Find the login route
        for (var route in $route.routes) {
        	if ($route.routes[route].login) {
        		loginRoute = $route.routes[route].originalPath;
        		break;
        	}
        }

        // The service
        return {
        	// Initialize the service
        	init: function(config) {
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
    			$rootScope.$on('$routeChangeSuccess', function(ev, data) {
    				// Check if this route is protected
    				if (data.$$route && data.$$route.public !== true && status.authorized == false) {
    					// redirect to login route
    		            $location.path(loginRoute);
    		            if (!$rootScope.$$phase) $rootScope.$apply();
    				}
    			});
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

                token = null;
                status.authorized = false;

                // Remove session cookie
    			Kaka.remove('ua_session_token');

                for (var key in user) {
                    delete user[key];
                }

                // redirect to login route
                $location.path(loginRoute);

                if (!$rootScope.$$phase){
                    $rootScope.$apply();
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
                    $rootScope.user.authorized = true;

                    // Set session cookie
                    Kaka.set('ua_session_token', token);
                }
                
                return token;
            },

            // Activate the session (set token, load user, start heartbeat, trigger event)
            activate: function(token, callback) {
                this.token(token);
                this.startHeartbeat();

                if ($route.current && loginRoute) {
    	            if ($route.current.$$route.originalPath == loginRoute) {
    	            	// redirect to default route
    	            	$location.path(defaultRoute);
    	            }
    	        }

                // Load the logged in user
                this.loadUser(function(error, result) {
                    callback && callback(error, result);
                    $rootScope.$broadcast('user.login');
                });
    		},

            // Sign up a new user and logs in
            signup: function(user, callback) {
                var that = this;
                
                UserApp.User.save(user, function(error, result) {
                    if (!error) {
                        // Success - Log in the user
                        that.login(user);
                    }

                    callback && callback(error, result);
                });
            },

            // Start new session / Login user
            login: function(user, callback) {
                var that = this;
                this.reset();

                UserApp.User.login(user, function(error, result) {
                    if (!error && !result.lock_type) {
                        that.activate(result.token, function() {
                            callback && callback(error, result);
                        });
                    } else {
                        callback && callback(error, result);
                    }
                });
            },

            // End session / Logout user
            logout: function(callback) {
                var that = this;

                UserApp.User.logout(function(error) {
                    if (!error) {
                        that.reset();
                        $rootScope.$broadcast('user.logout');
                    }

                    callback && callback(error);
                });
            },

            // Check if the user has permission
            hasPermission: function(permissions) {
                if (!this.current.permissions || !permissions) {
                    return false;
                }

                if (typeof(permissions) != "object") {
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
                if (!this.current.features || !features) {
                    return false;
                }

                if (typeof(features) != "object") {
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
                        angular.extend(user, result[0]);
                        if (!$rootScope.$$phase) {
                            $rootScope.$apply();
                        }
                    }

                    callback && callback(error, result);
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
                        }
                    });
                }, interval || 20000);
            }
    	};
    });

    // Logout directive
    userappModule.directive('uaLogout', function(user) {
    	return {
    		restrict: 'A',
    		link: function(scope, element, attrs) {
    			element.on('click', function(e) {
    				e.preventDefault();
    				user.logout();
    				return false;
    			});
    		}
    	};
    });

    // Login directive
    userappModule.directive('uaLogin', function($rootScope, user) {
    	return {
    		restrict: 'A',
    		link: function(scope, element, attrs) {
    			element.on('submit', function(e) {
    				e.preventDefault();

    				user.login({ login: this.login.value, password: this.password.value }, function(error, result) {
    					if (error) {
                            return handleError(scope, error, attrs.uaError);
    					}
    				});

    				return false;
    			});
    		}
    	};
    });

    // Signup directive
    userappModule.directive('uaSignup', function($rootScope, user, UserApp) {
        return {
            restrict: 'A',
            link: function(scope, element, attrs) {
                element.on('submit', function(e) {
                    e.preventDefault();

                    // Create the sign up object
                    var object = {};
                    for (var i = 0; i < this.elements.length; ++i) {
                        if (this.elements[i].name) {
                            object[this.elements[i].name] = this.elements[i].value;

                            if (angular.element(this.elements[i]).attr("ua-is-email") != undefined) {
                                object["email"] = this.elements[i].value;
                            }
                        }
                    }
                    
                    // Sign up
                    user.signup(object, function(error, result) {
                        if (error) {
                            if (error) {
                                return handleError(scope, error, attrs.uaError);
                            }
                        }
                    });

                    return false;
                });
            }
        };
    });

    // OAuth URL directive
    userappModule.directive('uaOauthLink', function(UserApp) {
        return {
            restrict: 'A',
            link: function(scope, element, attrs) {
                element.on('click', function(e) {
                    e.preventDefault();

                    var providerId = attrs.uaOauthLink;
                    var scopes = 'uaOauthScopes' in attrs ? (attrs.uaOauthScopes || "").split(',') : null;
                    var defaultRedirectUrl = window.location.protocol+"//"+window.location.host+window.location.pathname+"#/oauth/callback/";
                    var redirectUri = 'uaOauthRedirectUri' in attrs ? attrs.uaOauthRedirectUri : defaultRedirectUrl;

                    UserApp.OAuth.getAuthorizationUrl({ provider_id: providerId, redirect_uri: redirectUri, scopes: scopes }, function(error, result){
                        if (error) {
                            return handleError(scope, error, attrs.uaError);
                        }else{
                            window.location.href = result.authorization_url;
                        }
                    });

                    return false;
                });
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