var winston = require('winston');
winston.configure({
    transports: [
        new(winston.transports.File)({
            name: 'info-file',
            filename: './logs/' + Math.floor(Date.now() / 1000) + '.log',
            level: 'info'
        }),
        new(winston.transports.File)({
            name: 'error-file',
            filename: './logs/' + Math.floor(Date.now() / 1000) + '.error.log',
            level: 'error'
        }),
        new(winston.transports.Console)()
    ]
});
// Confirm some credentials are available:
try {
    var credentials = require('./credentials.js');
    var setup = require('./setup.js');
} catch (e) {
    throw ("Either you haven't setup credentials.js or you haven't got a setup.js file");
}
//Console.log redirect
console.logCopy = console.log.bind(console);
console.log = function(data) {
    var currentDate = '[' + new Date().toUTCString() + '] ';
    this.logCopy(currentDate, data);
};

var signedInUsers = [];
var signedInUsersFile = 'signedInUsers.json';
var systemInfoFile = [];
//Temporary persistent files
var fs = require('fs');
if (fs.existsSync(signedInUsersFile)) {
    winston.log('info', "Loading existing signedInUsers variable");
    signedInUsers = JSON.parse(fs.readFileSync(signedInUsersFile));
    winston.log('info', signedInUsers);
}

//Grab list of systems
var listOfBRSystems = JSON.parse(fs.readFileSync('systems.json', 'utf8'));
//Creating a generic flat list of all the systems to confirm against so people don't fuck about with submitting to non-existant things
var flatListOfBRSystems = [];
var regionList = Object.keys(listOfBRSystems);
for (var i = 0; i < regionList.length; i++) {
    var constellationList = Object.keys(listOfBRSystems[regionList[i]]);
    for (var x = 0; x < constellationList.length; x++) {
        var systemList = Object.keys(listOfBRSystems[regionList[i]][constellationList[x]]);
        for (var y = 0; y < systemList.length; y++) {
            flatListOfBRSystems.push(systemList[y]);
        }
    }
}

var submittedReports = [];

function saveFiles() {
    fs.writeFile(signedInUsersFile, JSON.stringify(signedInUsers), 'utf8', function(err) {
        if (err) winston.log('info', err);
        //winston.log('info', 'signedInUsers.json saved');
    });
    fs.writeFile("submittedReports.json", JSON.stringify(submittedReports), 'utf8', function(err) {
        if (err) winston.log('info', err);
    });
}

setInterval(function() {
    saveFiles();
}, 10000);

// Global Vars:
var EVE_SSO_CLIENTID = credentials.client_id;
var EVE_SSO_SECRET = credentials.client_secret;
var EVE_SSO_CALLBACK_URL = credentials.callback_url;

var EVE_SSO_HOST = 'login.eveonline.com';
//var EVE_SSO_HOST = 'sisilogin.testeveonline.com';

// Set a string that identifies your app as the user agent:
var MY_USER_AGENT = 'express 4.9.5, eve-sso, goons-auth 1.0.0, EVE client_id ' + EVE_SSO_CLIENTID;

var url = require('url');
var path = require('path');

var request = require('request');
var express = require('express');
var cookieParser = require('cookie-parser');
var md5 = require('js-md5');
var btoa = require('btoa');
var bodyParser = require('body-parser');

var app = express();
var router = express.Router();

app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));

//Sockets
var http = require('http');
var server = http.createServer(app);
var io = require('socket.io').listen(server);

server.listen(8767);
// Requests are passed through the chain of app.use() request handlers in order,
// until something throws an error or sends a response:

// First, log incoming requests:
app.use(function(req, res, next) {
    //winston.log('info', '%s %s', req.method, req.url);
    next(); // calling the next argument tells express to hand the request down the chain
});

// Pass anything that wasn't served as static to the router:
app.use(router);

// Pass any unrouted requests and exceptions to an error handler:
app.use(function(err, req, res, next) {
    // a count of four function arguments tells express this is an error handler
    console.error(err);
    console.error(err.stack);
    res.status(500).send('Internal Server Error');
})

/* 
 *  ROUTES
 */

// We have only two SSO-specific routes:
//   /evesso/begin:    redirect a user to CCP
//   /evesso/callback: CCP redirects the user here with an code after login

// Respect CCP's api by sending a unique user agent:
router.all('*', function(req, res, next) {
    res.setHeader('User-Agent', MY_USER_AGENT)
    next();
});

//Static routes for CSS and JS and such
app.use('/static', express.static('public'));

// STEP 0. Render a 'Sign on with EVE SSO' button that goes to our own route /evesso/begin
// You could template the appropriate EVE_SSO_HOST URL into the client html and skip this step,
// but that means CCP sees a browser user-agent on the initial request, instead of yours
router.get('/', function(req, res) {
    checkLogin(req.cookies, function(permitted, user, isAdmin) {
        if (!permitted) {

            var content = `
    
    `;
            var html =  content;
            res.status(200).send(generateHTML(`
                <p>Hi - Welcome to BRIGADE. You need to be whitelisted to use this service, please log in below.</p><p>
    <div>
        <a href="/evesso/begin">
        <img src="/static/img/EVE_SSO_Login_Buttons_Large_Black.png" style="margin: auto;">
        </a>
    </div></p>`, "Home", permitted, isAdmin, false));
        } else {
            res.status(302).redirect('/home');
        }
    });
});

// STEP 1. Redirect user to CCP, where they login.
router.get('/evesso/begin', function(req, res) {
    try {

        // example oauth start URI, from CCP docs (linked at top):
        // https://
        //    login.eveonline.com
        //       /oauth/authorize/
        //          ?response_type=code
        //          &redirect_uri=https://3rdpartysite.com/callback
        //          &client_id=3rdpartyClientId
        //          &scope=
        //          &state=uniquestate123

        var urlObj = {
            protocol: 'https',
            host: EVE_SSO_HOST,
            pathname: '/oauth/authorize',
            query: {
                response_type: 'code',
                redirect_uri: EVE_SSO_CALLBACK_URL, // This must exactly match what you set on CCP's site
                client_id: EVE_SSO_CLIENTID,
                scope: 'characterLocationRead publicData fleetRead fleetWrite characterNavigationWrite',
                state: 'stateless',
            },
        };

        // Use node's url library to assemble the URL:
        var ssoBeginURL = url.format(urlObj);

        // User agent was already set by previous middleware. Redirect user to EVE_SSO_HOST:
        res.redirect(302, ssoBeginURL);
    } catch (e) {
        winston.log('info', e)
    }
});


// STEP 2. CCP redirects the user from their /oauth/authorize to our /evesso/callback with an auth code,
// We will make two requests to CCP before sending any response to the user's request for /evesso/callback.

router.get('/evesso/callback', function(req, res) {
    try {
        //winston.log('info', 'Got redirected to /evesso/callback by CCP')

        var authCode = req.query['code'];

        // STEP 3. We have a one-time-use auth code from CCP in the /evesso/callback query string.
        // We must make a request with our secret and code, to get a token for this user:
        requestToken(authCode, function(err, response3, bodyObj) {
            // Now that we're in this callback, requestToken() completed its request/response.

            if (!err && response3.statusCode == 200) {
                var token = bodyObj.access_token;
                var charRefresh = bodyObj.refresh_token;
                //winston.log('info', bodyObj);

                // STEP 4. We have a token from /oauth/token
                // We must make a request with the token to get CharacterID:
                requestCharacterID(token, function(err, response4, bodyObj) {
                    //winston.log('info', `Character Name: ${bodyObj.CharacterName}\nCharacter ID: ${bodyObj.CharacterID}`);
                    //winston.log('info', bodyObj);
                    // Now that we're in this callback, requestCharacterID() completed its request/response.
                    requestCharacterInfo(token, bodyObj.CharacterID, function(err, response5, charInfoBody) {

                        if (!err && response4.statusCode == 200) {
                            var charId = bodyObj.CharacterID;
                            var charName = bodyObj.CharacterName;
                            var alliance = undefined;
                            if (typeof charInfoBody == 'object') {
                                alliance = charInfoBody.alliance;
                            }
                            var isAdmin = false;
                            if (setup.admins.includes(charName)) {
                                isAdmin = true;
                            }
                            var isSuperAdmin = false;
                            if (setup.superadmins.includes(charName)) {
                                isSuperAdmin = true;
                            }
                            if (typeof alliance == 'undefined' || !setup.alliances.includes(alliance.toString()) || setup.blacklist.includes(charName)) {
                                text = "You are either not whitelisted to use this service or banned. Please contact SIG leadership in incursions@jabber.goonfleet.com if you believe this to be incorrect.";
                                res.send(text);
                            } else {
                                var superSecretCookieData = md5(btoa(charId * 1337));
                                res.cookie("gooncookie", superSecretCookieData, {
                                    maxAge: 604800000
                                }).send('<a href="/home/">Continuing...</a><script>setTimeout(function() {window.location.href = "/home"},200)</script>'); //Cookies last a day
                                //Now we can save that info in our local objects
                                var multiLoginFail = false;
                                for (var i = 0; i < signedInUsers.length; i++) {
                                    if (signedInUsers[i].charId == charId) {
                                        multiLoginFail = true;
                                    }
                                }
                                if (!multiLoginFail) {
                                    winston.log('info', Object.keys(bodyObj));
                                    winston.log('info', bodyObj);
                                    signedInUsers.push({
                                        charId: charId,
                                        charName: charName,
                                        alliance: alliance,
                                        cookie: superSecretCookieData,
                                        isAdmin: isAdmin,
                                        isSuperAdmin: isSuperAdmin,
                                        uniqueId: Math.floor(Math.random() * 2701583) + 1,
                                        token: token,
                                        refresh_token: charRefresh
                                    });
                                }
                            }

                        } else {
                            winston.log('info', err);
                            winston.log('info', response4.body);
                            return res.status(500).send('API error');
                        }
                    });
                });
            }
        });
    } catch (e) {
        winston.log('info', e);
    }
});


function getNewToken(refreshtoken, callback, passthrough) {
    try {

        // Build URL for token request:
        var urlObj = {
            protocol: 'https',
            host: EVE_SSO_HOST,
            pathname: '/oauth/token',
        }
        var ssoTokenUrl = url.format(urlObj);

        // Build the authentication string:
        var tokenAuthHeaderString =
            "Basic " +
            base64ify(EVE_SSO_CLIENTID + ":" + EVE_SSO_SECRET);

        // Set up options for the post request:
        var postOptions = {
            url: ssoTokenUrl,
            headers: {
                "Authorization": tokenAuthHeaderString,
                //"Host": EVE_SSO_HOST,
                "User-Agent": MY_USER_AGENT,
            },
            form: {
                grant_type: 'refresh_token',
                refresh_token: refreshtoken,
            }
        }

        // Send request:
        request.post(postOptions, function(err, response, body) {
            // Handle response:
            if (!err && response.statusCode == 200) {
                var bodyObj = JSON.parse(body);
                winston.log('info', bodyObj);
                callback(bodyObj, passthrough)
            } else {
                callback(err);
                //winston.log('info', response);
            }
        });
    } catch (e) {
        winston.log('info', e);
    }
}

function requestToken(authCode, callback) {
    try {
        // Build URL for token request:
        var urlObj = {
            protocol: 'https',
            host: EVE_SSO_HOST,
            pathname: '/oauth/token',
        }
        var ssoTokenUrl = url.format(urlObj);

        // Build the authentication string:
        var tokenAuthHeaderString =
            "Basic " +
            base64ify(EVE_SSO_CLIENTID + ":" + EVE_SSO_SECRET);

        // Set up options for the post request:
        var postOptions = {
            url: ssoTokenUrl,
            headers: {
                "Authorization": tokenAuthHeaderString,
                //"Host": EVE_SSO_HOST,
                "User-Agent": MY_USER_AGENT,
            },
            form: {
                grant_type: 'authorization_code',
                code: authCode,
            }
        }

        // Send request:
        request.post(postOptions, function(err, response, body) {
            // Handle response:
            if (!err && response.statusCode == 200) {
                var bodyObj = JSON.parse(body);
                callback(null, response, bodyObj)
            } else {
                callback(err, response);
                //winston.log('info', response);
            }
        });
    } catch (e) {
        winston.log('info', e);
    }
}

function requestCharacterID(token, callback) {
    try {
        // Build URL for verify request:
        var urlObj = {
            protocol: 'https',
            host: EVE_SSO_HOST,
            pathname: '/oauth/verify',
        }
        var ssoVerifyUrl = url.format(urlObj);

        // Build the auth header from recently acquired token:
        var verifyAuthHeaderString = "Bearer " + token;

        // Set up options for the get request:
        var getOptions = {
            url: ssoVerifyUrl,
            headers: {
                "Authorization": verifyAuthHeaderString,
                "User-Agent": MY_USER_AGENT,
            }
        }


        // Send response:
        request.get(getOptions, function(err, response, body) {
            if (!err && response.statusCode == 200) {
                var bodyObj = JSON.parse(body);
                callback(null, response, bodyObj)
                winston.log('info', bodyObj);
            } else {
                callback(err, response);
            }
        });
    } catch (e) {
        winston.log('info', e);
    }
}

function requestCharacterInfo(token, charID, callback) {
    try {
        //var ssoVerifyUrl = url.format(urlObj);
        var ssoVerifyUrl = `https://api.eveonline.com/eve/CharacterInfo.xml.aspx?characterID=${charID}`;
        // Send response:
        request.get(ssoVerifyUrl, function(err, response, body) {
            if (!err && response.statusCode == 200) {
                var parseString = require('xml2js').parseString;
                parseString(body, function(err, result) {
                    winston.log('info', result);
                    callback(null, response, result.eveapi.result[0]);
                });

            } else {
                callback(err, response);
            }
        });
    } catch (e) {
        winston.log('info', e);
    }
}

function getCharacterIdFromName(name, callback) {
    try {
        var url = "https://api.eveonline.com/eve/CharacterID.xml.aspx?names=";

        request.get(url + encodeURIComponent(name), function(err, res, body) {
            if (!err && res.statusCode == 200) {
                var parseString = require('xml2js').parseString;
                parseString(body, function(err, result) {
                    callback(result.eveapi.result[0].rowset[0].row[0]["$"].characterID);
                });
            } else {
                winston.log('info', err)
                callback(res);
            }
        });
    } catch (e) {
        winston.log('info', e);
    }
}

function getCharacterAllianceFromId(id, callback) {
    try {
        requestCharacterInfo(null, id, function(err, res, result) {
            if (typeof result !== 'undefined') {
                winston.log('info', typeof result);
                if (typeof result.alliance !== 'undefined') {
                    winston.log('info', typeof result.alliance);
                    winston.log('info', typeof result.alliance[0]);
                    callback(result.alliance[0]);
                } else {
                    callback(undefined);
                }
            } else {
                callback(undefined);
            }
            //I know this is dumb, shut up, undefined's are hard to deal with and it wasn't liking me combining it into one statement for some reason
        });
    } catch (e) {
        winston.log('info', e);
    }
}


/* 
 *  UTILITY
 */
function base64ify(input) {
    // we use this to craft the Authentication header for token request:
    var authHeader = new Buffer(input, 'utf8').toString('base64');
    return authHeader;
}

function checkLogin(cookie, callback) {
    try {
        var permitted = false;
        var user;
        var isAdmin;
        var isSuperAdmin;
        if (signedInUsers.length > 0) {
            for (var i = 0; i < signedInUsers.length; i++) {
                if (cookie.gooncookie == signedInUsers[i].cookie) {
                    user = signedInUsers[i];
                    permitted = true;
                    isAdmin = signedInUsers[i].isAdmin;
                    isSuperAdmin = signedInUsers[i].isSuperAdmin;
                }
            }
        }
        callback(permitted, user, isAdmin, isSuperAdmin);
    } catch (e) {
        winston.log('info', e);
    }
}
//Home Page
router.get('/home/', function(req, res) {
    checkLogin(req.cookies, function(permitted, user, isAdmin, isSuperAdmin) {
        if (permitted) {
            res.status(200).send(generateHTML("<p>Welcome to the BRIDAGE.</p><p>This service exist to stop you from PMing Joe Barbarian. Seriously. He paid me for it so you wouldn't bug him.</p><p>Anyway, hit 'Submit Info' on the left to submit information that could help us track the Blood Raider Sotiyo's.", "Home", permitted, isAdmin, isSuperAdmin));
        } else {
            res.status(302).redirect('/');
        }
    });
});

//List systems
router.get('/system/:system', function(req, res) {
    checkLogin(req.cookies, function(permitted, user, isAdmin, isSuperAdmin) {
        if (permitted) {
            if (flatListOfBRSystems.includes(req.params.system)) {
                res.status(200).send(generateHTML(`<p>Here, you can submit information for the system <b>${req.params.system}</b>.</p> <p>You should include information such as:<br>
                    <ul>
                        <li>Which asteroid belt(s) you found miners/haulers in (ex. M4B3 & M4B6)</li>
                        <li>Their fleet composition (ex. 4 Covetors, 2 Hulks in M4B3, 8 Ventures in M4B6)</li>
                        <li>If you saw a hauler, and if so, when the last time was</li>
                        <li>Whether said hauler was an Impel or Bestower</li>
                        <li>If you tried to follow a hauler back to their warp-off location, and if so, what the result was</li>
                        <li>Any other potentially useful information regarding <b>this system only</b></li>
                    </ul></p>
                    <div style="padding: 10px;">
                    <form action="/system/${req.params.system}" method="post">
                    Details:<br>
                    <textarea rows="20" cols="50" name="info"></textarea><br>
                    Time: <input name="time" id="time"></input> <font size="1">Note this is MY server time and not EVE server time - You should only change this if this information is older than a few minutes</font>
                    <br><button type='submit'>Submit</button>
                    </form>
                    </div>
                    <script>
                        var d = new Date();
                        document.getElementById("time").value = d.getHours() + ":" + d.getMinutes();
                    </script>
                    `, "Home", permitted, isAdmin, isSuperAdmin));
            } else {
                res.status(200).send(`Hello, ${user.charName}. You requested ${req.params.system}, which doesn't exist. If you think this is incorrect, contact Makeshift Storque on Jabber.
                    <br><br><a href="/home/">Click here to return to home</a>.
                    `);
            }
        } else {
            res.status(302).redirect('/');
        }
    });
});

//Actual submission handling
router.post('/system/:system', function(req, res) {
    checkLogin(req.cookies, function(permitted, user, isAdmin, isSuperAdmin) {
        if (permitted) {
            console.log(req.body)
            res.status(200).send(`Thank you for your submission for system ${req.params.system}. An admin will review it shortly.<br><br><a href="/home/">Go back to the homepage</a><br><br><a href="/system/">Submit more information</a>`);
            var saveObject = {
                system: req.params.system,
                user: user.charName,
                info: req.body.info,
                time: req.body.time
            };
            submittedReports.push(saveObject);
        } else {
            res.status(302).redirect('/');
        }
    });
});

//Grab system
router.get('/system/', function(req, res) {
    checkLogin(req.cookies, function(permitted, user, isAdmin, isSuperAdmin) {
        if (permitted) {
            var finalFormattedSystemList = "";
            var regionList = Object.keys(listOfBRSystems);
            for (var i = 0; i < regionList.length; i++) {
                finalFormattedSystemList += "<br><h2>" + regionList[i] + "</h2><br>";
                var constellationList = Object.keys(listOfBRSystems[regionList[i]]);
                for (var x = 0; x < constellationList.length; x++) {
                    finalFormattedSystemList += "<h3><pre>&#9;" + constellationList[x] + "</pre></h3><br>";
                    var systemList = Object.keys(listOfBRSystems[regionList[i]][constellationList[x]]);
                    for (var y = 0; y < systemList.length; y++) {
                        finalFormattedSystemList += `<pre>&#9;&#9;<a href='/system/${systemList[y]}'>${systemList[y]}</a></pre><br>`;
                    }
                }
            }
            res.status(200).send(generateHTML(finalFormattedSystemList, "Systems", permitted, isAdmin, isSuperAdmin));
        } else {
            res.status(302).redirect('/');
        }
    });
});


//Admin handling
router.get('/admin/', function(req, res) {
    checkLogin(req.cookies, function(permitted, user, isAdmin, isSuperAdmin) {
        if (permitted && isAdmin) {
            var regionList = Object.keys(listOfBRSystems);
            var content = "<div style='padding: 10px'>";
            for (var i = 0; i < regionList.length; i++) {
                content += `<h1>${regionList[i]}</h1><br>`;
                var constellationList = Object.keys(listOfBRSystems[regionList[i]]);
                for (var x = 0; x < constellationList.length; x++) {
                    content += `<h3>${constellationList[x]}</h3>`;
                    content += `
                        <table style="width: 100%">
                            <tr>
                                <th class="center" width="15%">System</th>
                                <th class="center" width="20%">Submitter</th>
                                <th width="50%">Submission</th>
                                <th class="center" width="15%">Delete</th>
                            </tr>`
                    var systemList = Object.keys(listOfBRSystems[regionList[i]][constellationList[x]]);
                    for (var y = 0; y < systemList.length; y++) {
                        content += `
                        <tr>
                            <td class="center">${systemList[y]}</td>
                            <td class="center"></td>
                            <td></td>
                            <td class="center"><button>Delete</button></td>
                        </tr>
                        `
                    }
                }
                content += "</div>";
                res.status(200).send(generateHTML(content, "Admin", permitted, isAdmin, isSuperAdmin));
            }
        } else {
            res.status(302).redirect('/');
        }
    });
});
















//HTML Generation Area
function generateHTML(content, title, loggedIn, isAdmin, isSuperAdmin) {

    //Menu Items
    var loggedInMenuItem = "";
    if (loggedIn) {
        loggedInMenuItem = "<p><a href='/system/'>Submit Info</a></p>";
    }
    var isAdminMenuItem = "";
    if (isAdmin) {
        isAdminMenuItem = "<p><a href='/admin/'>Admin Panel</a></p>";
    }
    var isSuperAdminMenuItem = "";
    if (isSuperAdmin) {
        isSuperAdminMenuItem = "<p><a href='/superadmin/'>Super Admin Panel</a></p>";
    }

    return `
    <!DOCTYPE html>
    <html>
    <head>
    <title>Sotiyo Brigade - ${title}</title>
    <!--[if IE]><script src="http://html5shiv.googlecode.com/svn/trunk/html5.js"></script><![endif]-->
    <link rel="stylesheet" type="text/css" href="/static/main.css" />
    </head>
    <body>
        <div id="wrapper">
            <div id="headerwrap">
            <div id="header">
                <p>Blood Raiders Intelligence Gathering Assistant for Damaging the Enemy<br><font size="1">(BRIGADE for short)</font></p>
            </div>
            </div>
            <div id="contentliquid""><div id="contentwrap" style="width:92%;">
            <div id="content">
               <p>${content}</p>
            </div>
            </div></div>
            <div id="leftcolumnwrap">
            <div id="leftcolumn">
                <p>
                   <p><a href="/home/">Home</a></p>
                   ${loggedInMenuItem}
                   ${isAdminMenuItem}
                   ${isSuperAdminMenuItem}
                </p>
            </div>
            </div>
            <div id="footerwrap">
            <div id="footer">
                By Makeshift - Catch me in the Incursions Jabber channel if something seems awry.
            </div>
            </div>
        </div>
    </body>
    </html>`;
}