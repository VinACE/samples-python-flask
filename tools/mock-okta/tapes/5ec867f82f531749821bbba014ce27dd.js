var path = require("path");

/**
 * POST /api/v1/authn
 *
 * host: rain.okta1.com:1802
 * connection: keep-alive
 * content-length: 121
 * origin: http://127.0.0.1:7777
 * x-okta-xsrftoken: 
 * user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:48.0) Gecko/20100101 Firefox/48.0
 * content-type: application/json
 * accept: application/json
 * x-requested-with: XMLHttpRequest
 * accept-encoding: gzip
 * accept-language: en-US
 * cache-control: no-cache, no-store
 * pragma: no-cache
 */

module.exports = function (req, res) {
  res.statusCode = 200;

  res.setHeader("server", "Apache-Coyote/1.1");
  res.setHeader("x-okta-request-id", "reqDPCGeydHTHWPoqYbN5aBYA");
  res.setHeader("x-rate-limit-limit", "1200");
  res.setHeader("x-rate-limit-remaining", "1199");
  res.setHeader("x-rate-limit-reset", "1478388289");
  res.setHeader("p3p", "CP=\"HONK\"");
  res.setHeader("set-cookie", ["sid=\"\"; Expires=Thu, 01-Jan-1970 00:00:10 GMT; Path=/","JSESSIONID=70AE96C8582376C33727D5332CA5E78A; Path=/","DT=DI0szFpmcNvRFaypiGqtGoNmA; Expires=Mon, 05-Nov-2018 23:23:50 GMT; Path=/"]);
  res.setHeader("cache-control", "no-cache, no-store");
  res.setHeader("pragma", "no-cache");
  res.setHeader("expires", "0");
  res.setHeader("content-type", "application/json;charset=UTF-8");
  res.setHeader("transfer-encoding", "chunked");
  res.setHeader("date", "Sat, 05 Nov 2016 23:23:49 GMT");

  res.setHeader("x-yakbak-tape", path.basename(__filename, ".js"));

  res.write(new Buffer("eyJleHBpcmVzQXQiOiIyMDE2LTExLTA2VDAxOjIzOjUwLjAwMFoiLCJzdGF0dXMiOiJTVUNDRVNTIiwic2Vzc2lvblRva2VuIjoiMjAxMTE5UDdmTkpET1QzRDI4Z1VOLW5qS0ZHTVdMdU8tcjQ0T2tPR29PcjY3NXZkZWlqOWlnSyIsIl9lbWJlZGRlZCI6eyJ1c2VyIjp7ImlkIjoiMDB1a3o0eVpVZ2lHMExJb1IwZzMiLCJwYXNzd29yZENoYW5nZWQiOiIyMDE2LTEwLTMwVDA0OjE5OjE0LjAwMFoiLCJwcm9maWxlIjp7ImxvZ2luIjoiZ2VvcmdlQGFjbWUuY29tIiwiZmlyc3ROYW1lIjoiR2VvcmdlIiwibGFzdE5hbWUiOiJXYXNoaW5ndG9uIiwibG9jYWxlIjoiZW5fVVMiLCJ0aW1lWm9uZSI6IkFtZXJpY2EvTG9zX0FuZ2VsZXMifX19fQ==", "base64"));
  res.end();

  return __filename;
};
