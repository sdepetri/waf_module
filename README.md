## Description

This module provides a web application firewall that has the following rules:
- To block incoming traffic from the given countries. Anyway, could also be implemented to allow traffic from a country.
- To Block the top 10 of most common vulnerabilities for Web Application

### OWASP - Rules implemented

1- A1- SQL Injection Attack
  
This rule looks for matches patterns in the request:
 - BODY
 - QUERY_STRING
 - URI
 - HEADER[Cookie]
 - HEADER[Authorization]

2- A2- Bad Authentication Tokens

It looks for matches patterns in the cookie or Authorization header, comparing with the values in a list of Bad or Hijacked Authorization Tokens. WAF can only act in a reactive mode because it doesn't have a way to know if a token was stolen, so, if there's any suspicious of tokens leakage, please change it and set it in the blacklist.
There's also implemented a rule that blocks IP that's trying to access the site after 100 failures in  5 minutes.

3- A3- Cross Site Scripting attack

It look for matches attempted XSS patterns in the URI, QUERY_STRING, BODY, COOKIES.

4- A4- Broken Access Control

It filters dangerous HTTP request patterns that can indicate path traversal attempts, or remote and local file inclusion (RFI/LFI). 

5- A7- Mitigate abnormal requests via size restrictions

This rule pretends to enforce a level of hygiene for inbound HTTP requests, ensuring that components of HTTP requests fall within specifically defined ranges for URI, QUERY STRING, BODY, COOKIE and X-API-KEY 

6- A8- Check the presence of CSRF token in the request header

If we Include unpredictable tokens in the HTTP request to validate the URL path and HTTP request that is intended to cause a state change, we can use WAF to detect if it is legitimate and wasn’t forged by a malicious party.

7- A9- Detect Server-side includes & libraries in webroot

It detects if there's a match  for request patterns for webroot objects that shouldn't be directly accessible.

## Resources

By adding this module to your project, you will create the following resources:

  - A Regional Web Application Firewall

  - Several Regional rules

  - Several Match Set Resources


## Usage

Include this repository as a module in your existing terraform code:

```hcl
module "waf" {
  source                 = "git@github.com:pulse360/terraform_modules.git//security//waf?ref=release/1.2.1"
  waf_name             = "rule_to_apply_in_the_environment"
  countries_blacklist    = ["CA","CN","HK"]
  sqli_action               = "COUNT"
  xss_action                = "COUNT"
  rfi_lfi_action            = "COUNT"
  size_constraints_action   = "COUNT"
  csrf_action               = "COUNT"
  ssi_action                = "COUNT"
  alb_arn                = "arn:aws:elasticloadbalancing:<region>:<account>:loadbalancer/app/pulse360-prod/b37f481d6b80c702"
}

```

## Inputs

|              Name              | Description                                                                        | Type         | Default                                                            | Required |
| :----------------------------: | ---------------------------------------------------------------------------------- | ------------ | ------------------------------------------------------------------ | :------: |
|            waf_name            | A prefix to use for all named resources.                                           | string       |                                                                    |   yes    |
|      countries_blacklist       | Blacklist of the countries whose traffic is gonna be blocked.                      | list(string) |                                                                    |   yes    |
|          rule_action           | The action of the rule: COUNT, BLOCK, DISABLED .                                   | string       | BLOCK                                                              |    no    |
|         rule_priority          | The execution priority of this rule.                                               | number       | 1                                                                  |    no    |
|          sqli_action           | The action desired for the SQLi mitigation rule.                                   | string       | COUNT                                                              |    no    |
|         sqli_priority          | The execution priority for the SQLi mitigation rule.                               | number       | 2                                                                  |    no    |
|      sqli_request_fields       | Target fields to look for SQLi attacks.                                            | list(string) | ["BODY", "URI", "QUERY_STRING"]                                    |    no    |
|      sqli_request_headers      | Target fields to look for SQLi attacks.                                            | list(string) | ["Cookie", "Authorization"]                                        |    no    |
|block_ip_login_exceeds_action| The action desired for the rule that blocks IP after several failed attempts to log in.| string       | COUNT                                                              |    no    |
|block_ip_login_exceeds_priority| The priority in which to execute this rule.                                        | number       | 2                                                                  |    no    |
|login_request| Autorization URLs or relevant applicationspecific URLs.| list(string) | ["/login"]                                    |    no    |
|           xss_action           | The action desired for the Detection of Bad auth tokens rule.                      | string       | COUNT                                                              |    no    |
|          xss_priority          | The priority in which to execute this rule.                                        | number       | 3                                                                  |    no    |
|       xss_request_fields       | Target fields to look for XSS attacks.                                             | list(string) | ["BODY", "URI", "QUERY_STRING"]                                    |    no    |
|      xss_request_headers       | Target fields to look for XSS attacks.                                             | list(string) | ["cookie"]                                                         |    no    |
|         rfi_lfi_action         | The action desired for the RFI/LFI rule.                                           | string       | COUNT                                                              |    no    |
|        rfi_lfi_priority        | The priority in which to execute this rule.                                        | number       | 4                                                                  |    no    |
|      rfi_lfi_querystring       | List of values to look for traversal attacks in the request query string.          | list(string) | ["://", "../"]                                                     |    no    |
|          rfi_lfi_uri           | List of values to look for traversal attacks in the request uri                    | list(string) | ["://", "../"]                                                     |    no    |
|    size_constraints_action     | The action desired for the limit size constrints rule.                             | string       | COUNT                                                              |    no    |
|   size_constraints_priority    | The priority in which to execute this rule.                                        | number       | 5                                                                  |    no    |
|     max_expected_uri_size      | Maximum number of bytes allowed in the URI component of the HTTP request.          | number       | 512                                                                |    no    |
| max_expected_query_string_size | Maximum number of bytes allowed in the query string component of the HTTP request. | number       | 1024                                                               |    no    |
|     max_expected_body_size     | Maximum number of bytes allowed in the body of the request.                        | number       | 4096                                                               |    no    |
|    max_expected_cookie_size    | Maximum number of bytes allowed in the cookie header.                              | number       | 4093                                                               |    no    |
|     min_expected_x_api_key     | Minimal size or the  actual size of the API key.                                   | number       | 1                                                                  |    no    |
|          csrf_action           | The action desired for the CSRF rule.                                              | string       | DISABLED                                                           |    no    |
|         csrf_priority          | The priority in which to execute this rule.                                        | number       | 6                                                                  |    no    |
|          csrf_header           | The name of the CSRF token header.                                                 | string       | x-csrf-token                                                       |    no    |
|           csrf_size            | The size of the CSRF token                                                         | number       | 36                                                                 |    no    |
|           ssi_action           | The action desired for SSI rule.                                                   | string       | COUNT                                                              |    no    |
|          ssi_priority          | The priority in which to execute this rule."                                       | number       | 7                                                                  |    no    |
|      ssi_file_extensions       | A blacklist of file extensions within the URI of a request.                        | list(string) | [".bak", ".backup", ".cfg", ".conf", ".config", ".ini", ".log"] no |
|           ssi_paths            | A blacklist of relative paths within the URI of a request                          | list(string) | ["/includes"]                                                      |    no    |
|            alb_arn             | ARN of the ALB to be associated with the WAF-ACL.                                  | string       |                                                                    |   yes    |


**countries_blacklist**: Two-letter country code format that can be checked here: https://docs.aws.amazon.com/waf/latest/APIReference/API_wafRegional_GeoMatchConstraint.html

**rule_action** refers to two possible actions that the waf can take when this rule is applied:
- COUNT: It counts the times that this rule occurs.
- BLOCK: it  blocks the access of the incoming traffic that matches this rule.

**rule_priority**: Rules with a lower value are evaluated before rules with a higher value. 

**sqli_request_fields**: HTTP request components to match. The most common are:

  * BODY:If the application accepts form input. WAF only evaluates the first 8 KB of the body content.
  
  * URI: If the application is using friendly, dirified URLs, then parameters might appear as part of the URL path segment, not the query string.
   
  * QUERY_STRING: Recommended if query string parameters are reflected back into the webpage.

**sqli_request_headers**: Less common components to match, related to database lookup, validation or any other value of the header that the application use. If any other components of custom request headers are used by the application as parameters for database lookups, they should be included. 
Typical values are:

  * Cookie: If the application uses cookie-based parameters in database lookups.
  
  * Authentication: If the application uses the value of this header for database validation

**rfi_lfi_querystring / rfi_lfi_uri**: Components of the HTTP request that the application uses to assemble or refer to file system paths. If there's someone missing, should be added.

**max_expected_uri_size**: Generally the maximum possible value is determined by the server operating system (maps to file system paths), the web server software, or other middleware components. Choose a value that accomodates the largest URI segment you use in practice in your web application.

**max_expected_query_string_size**: Normally the number of query string parameters following the ? in a URL is much larger than the URI , but still bounded by the  of the parameters your web application uses and their values.

**max_expected_body_size**: If you do not plan to allow large uploads, set it to the largest payload value that makes sense for your web application. Accepting unnecessarily large values can cause performance issues, if large payloads are used as an attack vector against your web application.

**max_expected_cookie_size**:  The maximum size should be less than 4096, the size is determined by the amount of information your web application stores in cookies. If you only pass a session token via cookies, set the size to no larger than the serialized size of the session token and cookie metadata.

**min_expected_x_api_key_size**: Te size of  the API key for a RESTful API.


## Outputs

|    Name    |            Description             |
| :--------: | :--------------------------------: |
| web_acl_id | The ID of the WAF Regional WebACL. |
