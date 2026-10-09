// sample.js — synthetic test fixture for jsrecon (all secrets are FAKE)
// TODO: remove the hardcoded admin password before shipping to prod
var config={apiBase:"https://api.internal.corp/v2",cdn:"//cdn.example.com/assets/app.js"};
var AWS_KEY="AKIAIOSFODNN7EXAMPLE";var aws_secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
var googleKey="AIzaSyA1234567890abcdefghijklmnopqrstuv0";
var stripe="sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH";
var slack="xoxb-123456789012-abcdefghijklmnopqrstuvwx";
var gh="ghp_abcdefghijklmnopqrstuvwxyz0123456789";
var jwt="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummysignaturevaluehere12345";
var password="SuperSecret123!";
var db="mongodb://root:toorpass@10.0.0.5:27017/app";
var endpoints=["/api/v1/users","/api/v1/admin/delete","/internal/debug/console","../config/keys.json","/login.php?redirect=home"];
fetch("https://backend.prod.example.com/api/v1/orders?id=1&token=abc").then(r=>r.json());
var adminEmail="root@example.com";
var bucket="https://my-secret-bucket.s3.amazonaws.com/private/dump.sql";
window.location.href = getParameterByName("next");      // open redirect candidate
document.getElementById("out").innerHTML = location.hash.substring(1);  // DOM XSS
eval(decodeURIComponent(location.search));
window.addEventListener("message", function(e){ document.write(e.data); });
var opts = { rejectUnauthorized: false, debug: true };
/* FIXME: internal endpoint, do not ship:  http://10.0.0.9:8080/private/api */
var ws = new WebSocket("wss://realtime.example.com/socket");
var gql = "https://api.example.com/graphql";
