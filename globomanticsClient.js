const express = require("express");
const url = require("url");
const bodyParser = require("body-parser");
const request = require("sync-request");
const randomString = require("randomstring");
const cons = require("consolidate");
const queryString = require("querystring");
const jose = require("jsrsasign");
const qs = require("qs");
const querystring = require("querystring");
const base64url = require("base64url");
const __ = require("underscore");
__.string = require("underscore.string");

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.engine("html", cons.underscore);
app.set("view engin", "html");
app.set("views", "files/client");

app.use("/", express.static("files/client"));
//authorization server inforamtion
const authServer = {
  authorizationEndpoint: "http://localhost:9003/authorize",
  tokenEndpoint: "http://localhost:9003/token",
};
//This is actually a public key from the authorization server so that the authorization server can sign the tokens,
// and we'll know that they came from the authServer we think they came from
let rsaKey = {
  alg: "RS256",
  e: "AQAB",
  n: "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
  kty: "RSA",
  kid: "authserver",
};
// client information
//client_secret need to store in vault in production
var client = {
  client_id: "globomantics-client-1",
  client_secret: "globomantics-client-secret-1",
  redirect_uris: ["http://localhost:9000/callback"],
  scope: "visits membershipTime averageWorkoutLength",
};
//protected resource api
var carvedRockGymApi = "http://localhost:9002/gymStats";

let state = null;
let access_token = null;
let refresh_token = null;
let scope = null;

app.get("/", (req, res) => {
  res.render("index", {
    access_token: access_token,
    refresh_token: refresh_token,
    scope: scope,
  });
});

app.get("/authorize", (req, res) => {
  access_token = null;
  refresh_token = null;
  scope = null;
  state = randomstring.generate();
  let authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
    response_type: "code",
    scope: client.scope,
    client_id: client.client_id,
    redirect_uri: client.redirect_uris[0],
    state: state,
  });
  console.log(authorizeUrl);
  res.redirect(authorizeUrl);
});

app.get("/callback", (req, res) => {
  if (req.query.error) {
    // it's an error response, act accordingly
    res.render("error", { error: req.query.error });
    return;
  }
  //CSRF check
  var resState = req.query.state;
  if (resState == state) {
    console.log("State value matches: expected %s got %s", state, resState);
  } else {
    console.log("State DOES NOT MATCH: expected %s got %s", state, resState);
    res.render("error", { error: "State value did not match" });
    return;
  }

  var code = req.query.code; //authorization code from query string
  var form_data = qs.stringify({
    grant_type: "authorization_code",
    code: code,
    redirect_uri: client.redirect_uris[0], //Now this is important because the redirect_uri will be validated on your authorization server as the same one we used before just to make sure, again, that it's talking to the same client that it talked to before and to make sure
    // there is nothing bad happening here
  });

  //We then have to authenticate our client to the authorization endpoint to prove that we are who we say we are. In this case,
  //we're using an Authorization header with HTTP Basic auth. So normally, this would be over TLS connections, so this would all be encrypted, and we are just creating our Base64 encoded string here of the client_id followed by a colon followed by the client_secret.
  var headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    Authorization:
      "Basic " +
      Buffer.from(
        querystring.escape(client.client_id) +
          ":" +
          querystring.escape(client.client_secret)
      ).toString("base64"),
  };

  var tokRes = request("POST", authServer.tokenEndpoint, {
    body: form_data,
    headers: headers,
  });
  console.log("Requesting access token for code %s", code);
  if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
    var body = JSON.parse(tokRes.getBody());

    access_token = body.access_token;
    console.log("Got access token: %s", access_token);
    if (body.refresh_token) {
      refresh_token = body.refresh_token;
      console.log("Got refresh token: %s", refresh_token);
    }

    if (body.access_token) {
      console.log("Got access token: %s", body.access_token);

      // check the access token
      var pubKey = jose.KEYUTIL.getKey(rsaKey);
      var signatureValid = jose.jws.JWS.verify(body.access_token, pubKey, [
        "RS256",
      ]);
      if (signatureValid) {
        console.log("Signature validated.");
        var tokenParts = body.access_token.split(".");
        var payload = JSON.parse(base64url.decode(tokenParts[1]));
        console.log("Payload", payload);
        if (payload.iss == "http://localhost:9003/") {
          console.log("issuer OK");
          // TODO: this is incorrect. Fix the video and the code
          if (
            (Array.isArray(payload.aud) &&
              _.contains(payload.aud, "http://localhost:9002/")) ||
            payload.aud == "http://localhost:9002/"
          ) {
            console.log("Audience OK");

            var now = Math.floor(Date.now() / 1000);

            if (payload.iat <= now) {
              console.log("issued-at OK");
              if (payload.exp >= now) {
                console.log("expiration OK");

                console.log("Token valid!");
              }
            }
          }
        }
      }
    }

    scope = body.scope;
    console.log("Got scope: %s", scope);

    res.render("index", {
      access_token: access_token,
      refresh_token: refresh_token,
      scope: scope,
    });
  } else {
    res.render("error", {
      error:
        "Unable to fetch access token, server response: " + tokRes.statusCode,
    });
  }
});
app.get("/gymStats", function (req, res) {
  if (!access_token) {
    if (refresh_token) {
      // try to refresh and start again
      refreshAccessToken(req, res);
      return;
    } else {
      res.render("error", { error: "Missing access token." });
      return;
    }
  }

  console.log("Making request with access token %s", access_token);

  var headers = {
    Authorization: "Bearer " + access_token,
    "Content-Type": "application/x-www-form-urlencoded",
  };

  var resource = request("GET", carvedRockGymApi, { headers: headers });

  if (resource.statusCode >= 200 && resource.statusCode < 300) {
    var body = JSON.parse(resource.getBody());
    res.render("gymStats", { scope: scope, data: body });
    return;
  } else {
    access_token = null;
    if (refresh_token) {
      // try to refresh and start again
      refreshAccessToken(req, res);
      return;
    } else {
      res.render("error", {
        error: "Server returned response code: " + resource.statusCode,
      });
      return;
    }
  }
});
//we have a helper function, and this helper function is refreshing the access_token. So if the access_token was expired or didn't work for some reason,
// we can refresh the token with our refresh_token. What that means is we'll get a brand-new access token without having the user click the Approve button again
const refreshAccessToken = function (req, res) {
  var form_data = qs.stringify({
    grant_type: "refresh_token",
    refresh_token: refresh_token,
    client_id: client.client_id,
    client_secret: client.client_secret,
    redirect_uri: client.redirect_uri,
  });
  var headers = {
    "Content-Type": "application/x-www-form-urlencoded",
  };
  console.log("Refreshing token %s", refresh_token);
  var tokRes = request("POST", authServer.tokenEndpoint, {
    body: form_data,
    headers: headers,
  });
  if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
    var body = JSON.parse(tokRes.getBody());

    access_token = body.access_token;
    console.log("Got access token: %s", access_token);
    if (body.refresh_token) {
      refresh_token = body.refresh_token;
      console.log("Got refresh token: %s", refresh_token);
    }
    scope = body.scope;
    console.log("Got scope: %s", scope);

    // try again
    res.redirect("/gymStats");
    return;
  } else {
    console.log("No refresh token, asking the user to get a new access token");
    // tell the user to get a new access token
    res.redirect("/authorize");
    return;
  }
};

const buildUrl = function (base, options, hash) {
  var newUrl = url.parse(base, true);
  delete newUrl.search;
  if (!newUrl.query) {
    newUrl.query = {};
  }
  __.each(options, function (value, key, list) {
    newUrl.query[key] = value;
  });
  if (hash) {
    newUrl.hash = hash;
  }

  return url.format(newUrl);
};

let server = app.listen(9000, "localhost", function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log("OAuth Client is listening at http://%s:%s", host, port);
});
