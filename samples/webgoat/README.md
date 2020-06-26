# WebGoat

> WebGoat is a deliberately insecure application that allows interested developers just like you to test vulnerabilities commonly found in Java-based applications that use common and popular open source components.

_Source: https://owasp.org/www-project-webgoat/_

## Running the App

We used a docker image of WebGoat 7.1 for our testing with the command:

```
docker run --name webgoat --rm -d -p 8080:8080 webgoat/webgoat-7.1
```

## Scanning with sqlmap

Our testing was done on a variety of specific endpoints rather than using a crawling scan. We based our commands from a previous [public discussion](https://sourceforge.net/p/sqlmap/mailman/message/34536009/) on using sqlmap to exploit WebGoat.

The `sqlmap-webgoat.sh` script in this directory automates this scanning and takes several parameters, which are defined near the top of the file:

- `TARGET` - Base path for WebGoat
- `SESSIONID` - Value of a JSESSIONID cookie retrieved after signing in to WebGoat through your browser
- `CODEDX_EXPORT` - Boolean indicating whether to run XML export (should be `0` or `1`)

The `TARGET` parameter may be left as-is if using a local docker install, assuming that such an install will expose WebGoat at `localhost`. `SESSIONID` will need to be retrieved and updated again each time WebGoat is started. When testing, we signed in using the "admin" WebGoat account (`webgoat`/`webgoat`) to retrieve the JSESSIONID cookie.

## Running the Script

```
cd samples/webgoat
sh sqlmap-webgoat.sh
```

The `sqlmap-webgoat.sh` file does not take parameters; you can modify the variables mentioned above and simply run the script directly.

This testing script creates the directories `logs-webgoat` and `output-webgoat`, containing log files and XML files respectively. Within these folders, subfolders are created based on current date and time to make it easier to compare results of different runs after making a change.
