---
title: "Intigriti 0125 XSS Challenge"
date: 2025-01-19T21:26:29+05:30
draft: false
---





**tl;dr**

* Abusing URL parsing implemented using Regex .
* Bypassing filters to using Path Normalization .
* Finally XSS !!.



<!--more-->
Intigriti dropped another Interesting XSS challenge,This time created by [0xGodson_](https://x.com/0xGodson_) .
## 🔎 Challenge Overview

The challenge is straightforward: it provides an input text box where we can enter our input, and it displays the output accordingly.

There is no server-side component to this challenge, all functionality is handled entirely on the client-side JavaScript my favorite kind of challenge!

```js 
function XSS() {
            return decodeURIComponent(window.location.search).includes('<') || decodeURIComponent(window.location.search).includes('>') || decodeURIComponent(window.location.hash).includes('<') || decodeURIComponent(window.location.hash).includes('>')
        }
        function getParameterByName(name) {
            var url = window.location.href;
            name = name.replace(/[\[\]]/g, "\\$&");
            var regex = new RegExp("[?&]" + name + "(=([^&#]*)|&|#|$)");
            results = regex.exec(url);
            if (!results) return null;
            if (!results[2]) return '';
            return decodeURIComponent(results[2].replace(/\+/g, " "));
        }

        // Function to redirect on form submit
        function redirectToText(event) {
            event.preventDefault();
            const inputBox = document.getElementById('inputBox');
            const text = encodeURIComponent(inputBox.value);
            window.location.href = `/challenge?text=${text}`;
        }

        // Function to display modal if 'text' query param exists
        function checkQueryParam() {
            const text = getParameterByName('text');
            if (text && XSS() === false) {
                const modal = document.getElementById('modal');
                const modalText = document.getElementById('modalText');
                modalText.innerHTML = `Welcome, ${text}!`;
                textForm.remove()
                modal.style.display = 'flex';
            }
        }

     window.onload = function () {
                generateFallingParticles();
                checkQueryParam();
            };

```

Examining the code, we can see that our input is stored in the **text** variable and eventually ends up in the **innerHTML** sink, suggesting an easy XSS. However, we need to make the **XSS()** function return **true**.  

The **XSS()** function checks for **<** and **>** characters in the **window.location.search** and **window.location.hash** parts of the URL. This means that if we input **?text=\<img src=x onerror=alert()>**, it will be blocked because **window.location.search** contains **<** and **>**.


![image](https://hackmd.io/_uploads/B1kLj9qwkx.png)

## 🥷 Attack plan

Looking at how the **text** parameter is being parsed in the **getParameterByName()** function, we can see that it is being parsed using a Regex that checks for a match in the entire URL.

As you can see, the **XSS()** check for starting **<** and closing **>** occurs on **window.location.search** and **window.location.hash**, but the URL parameter **text** is being parsed using Regex from **window.location.href**, which contains the entire URL.

So if we manage to sneak in our payload somewhere other than the search part or the hash part of the URL, it will be parsed by the Regex and will end up in the innerHTML sink.

What if we give it in the path part of the URL?!  

Like this:  ``https://challenge-0125.intigriti.io/&text=<payload>/../challenge``

Here, the Regex will parse it, and the search part and hash part of the URL are empty and don't contain starting **<** and closing **>**, so the payload will reach the innerHTML sink and pop `alert()`.


Make sure to URL encode the **/** !!
## 🚀  Final Payloads

**https://challenge-0125.intigriti.io/&text=%3Cimg%20src=x%20onerror=alert()%3E%2f../challenge**

## 💀 Exploit !!

![image](https://hackmd.io/_uploads/By0cyicvyl.png)


