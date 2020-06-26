# PESQLi

We were looking for a simple test application for "parametric endpoints", which are endpoints that have a parameter as part of their path such as `/posts/{id}`.

PESQLi is a sample application based on ASP.NET Core 3.1 that is designed to be vulnerable to SQL injections via endpoint parameters. Source code can be found at: https://github.com/tylercamp/PESQLi

Instructions for building, downloading, and running the application are provided in the repository's README. We suggest downloading one of the pre-built executables in the [releases section.](https://github.com/tylercamp/PESQLi/releases/)

## Sample Commands

```
python sqlmap.py \
    -u "http://localhost:5000/cms/foo*" \
    --dbms SQLite \
    --flush-session \
    --batch
```