
# DVWA (Damn Vulnerable Web Application)

> Damn Vulnerable Web App (DVWA) is a PHP/MySQL web application that is damn vulnerable. Its main goals are to be an aid for security professionals to test their skills and tools in a legal environment, help web developers better understand the processes of securing web applications and aid teachers/students to teach/learn web application security in a class room environment.

_Source: http://www.dvwa.co.uk/_

## Running the App

We used a docker image of DVWA provided by GitHub user [opsxcq](https://github.com/opsxcq); more information can be found at: https://github.com/opsxcq/docker-vulnerable-dvwa

```
docker run --rm -d --name dvwa -p 80:80 vulnerables/web-dvwa
```

## Sample Commands

The main test for DVWA was done with web-crawling. To run the sqlmap command, you'll first need to connect to DVWA in your browser. Sign in with credentials `admin`/`password` and you should be brought to a "Database Setup" page. Simply click the `Create / Reset Database` button and wait for the operation to finish. You'll be brought back to the login page; sign in again using the same credentials, and extract the value of the `PHPSESSID` cookie. (Example cookie value: `pat2pt3g39crmiunjad8aikhc2`)

Modify the command below and replace the `<SESSIONID>` text on the second line with the `PHPSESSID` cookie you've extracted. Make sure to leave `;security=low` in the cookie parameter passed to sqlmap. After configuration, the following command should complete with at least 1 injection:

```
python sqlmap.py \
    --cookie="PHPSESSID=<SESSIONID>;security=low" \
    -u "http://localhost/" \
    --fresh-queries --dbms=MySQL --drop-set-cookie --flush-session \
    --crawl=4 \
    --answers="redirect=N,normalize=Y,skip=N" \
    --batch \
    --threads=1 \
    --forms \
    --crawl-exclude="setup|logout|login|google|captcha|security|csrf"
```