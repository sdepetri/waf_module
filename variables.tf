variable "waf_name" {
  type        = string
  description = "A prefix to use for all named resources."
}
variable "countries_blacklist" {
  type        = list(string)
  description = "A blacklist of countries."
}
variable "rule_action" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "BLOCK"
}
variable "rule_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 1
}

variable "sqli_action" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "sqli_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 2
}
variable "sqli_request_fields" {
  type        = list(string)
  description = "A list of fields in the request to look for SQLi attacks."
  default     = ["BODY", "URI", "QUERY_STRING"]
}
variable "sqli_request_headers" {
  type        = list(string)
  description = "A list of headers in a request to look for SQLi attacks."
  default     = ["cookie", "authorization"]
}

variable "bad_auth_token_action" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "bad_auth_token_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 3
}
variable "auth_tokens_black_list" {
  type        = list(string)
  description = "A list of headers in a request to look for SQLi attacks."
  default     = []
}
variable "block_ip_login_exceeds_action" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "block_ip_login_exceeds_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 4
}
variable "login_request" {
  type        = list(string)
  description = "A list of headers in a request to look for SQLi attacks."
  default     = ["/login"]
}

variable "xss_action" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "xss_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 5
}
variable "xss_request_fields" {
  type        = list(string)
  description = "A list of fields in the request to look for XSS attacks."
  default     = ["BODY", "URI", "QUERY_STRING"]
}
variable "xss_request_headers" {
  type        = list(string)
  description = "A list of headers in the request to look for XSS attacks."
  default     = ["Cookie"]
}

variable "rfi_lfi_action" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "rfi_lfi_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 6
}
variable "rfi_lfi_querystring" {
  type        = list(string)
  description = "A list of values to look for traversal attacks in the request querystring."
  default     = ["://", "../"]
}
variable "rfi_lfi_uri" {
  type        = list(string)
  description = "A list of values to look for traversal attacks in the request URI."
  default     = ["://", "../"]
}

variable "size_constraints_action" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "size_constraints_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 7
}
variable "max_expected_uri_size" {
  type        = number
  description = "Maximum number of bytes allowed in the URI component of the HTTP request. Generally the maximum possible value is determined by the server operating system (maps to file system paths), the web server software, or other middleware components. Choose a value that accomodates the largest URI segment you use in practice in your web application."
  default     = 512
}
variable "max_expected_query_string_size" {
  type        = number
  description = "Maximum number of bytes allowed in the query string component of the HTTP request. Normally the  of query string parameters following the ? in a URL is much larger than the URI , but still bounded by the  of the parameters your web application uses and their values."
  default     = 1024
}
variable "max_expected_body_size" {
  type        = number
  description = "Maximum number of bytes allowed in the body of the request. If you do not plan to allow large uploads, set it to the largest payload value that makes sense for your web application. Accepting unnecessarily large values can cause performance issues, if large payloads are used as an attack vector against your web application."
  default     = 4096
}
variable "max_expected_cookie_size" {
  type        = number
  description = "Maximum number of bytes allowed in the cookie header. The maximum size should be less than 4096, the size is determined by the amount of information your web application stores in cookies. If you only pass a session token via cookies, set the size to no larger than the serialized size of the session token and cookie metadata."
  default     = 4093
}
variable "min_expected_x_api_key_size" {
  type        = number
  description = "Minimal size or the  actual size of the API key"
  default     = 1
}

variable "csrf_action" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "csrf_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 8
}
variable "csrf_header" {
  type        = string
  description = "The name of your CSRF token header."
  default     = "x-csrf-token"
}
variable "csrf_size" {
  type        = number
  description = "The size of your CSRF token."
  default     = 36
}

variable "ssi_action" {
  type        = string
  description = "COUNT or BLOCK, any other value will disable this rule entirely."
  default     = "DISABLED"
}
variable "ssi_priority" {
  type        = number
  description = "The priority in which to execute this rule."
  default     = 9
}
variable "ssi_file_extensions" {
  type        = list(string)
  description = "A blacklist of file extensions within the URI of a request."
  default     = [".bak", ".backup", ".cfg", ".conf", ".config", ".ini", ".log"]
}
variable "ssi_paths" {
  type        = list(string)
  description = "A blacklist of relative paths within the URI of a request."
  default     = ["/includes"]
}

variable "alb_arn" {
  description = "ARN of the Application Load Balancer (ALB) to be associated with the Web Application Firewall (WAF) Access Control List (ACL)."
  type        = string
}