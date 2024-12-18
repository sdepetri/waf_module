# REGIONAL TRAFFIC MITIGATION
resource "aws_wafregional_rule" "country_of_origin_filter" {
  name        = "${var.waf_name}_countries_filter"
  metric_name = "${var.waf_name}CountriesFilter"

  predicate {
    data_id = aws_wafregional_geo_match_set.geo_match_set.id
    negated = false
    type    = "GeoMatch"
  }
}

resource "aws_wafregional_geo_match_set" "geo_match_set" {
  name  = "${var.waf_name}_geo_match_set"

  dynamic "geo_match_constraint" {
    iterator = x
    for_each = var.countries_blacklist
    content {
      type  = "Country"
      value = x.value
    }
  }
}

# OWASP - A1
resource "aws_wafregional_rule" "sqli_mitigation" {
  name        = "${var.waf_name}_sqli_mitigation"
  metric_name = "${var.waf_name}SqliMitigation"

  predicate {
    data_id = aws_wafregional_sql_injection_match_set.sqli_match_set.id
    negated = false
    type    = "SqlInjectionMatch"
  }
}

resource "aws_wafregional_sql_injection_match_set" "sqli_match_set" {
  name = "${var.waf_name}_sqli_match_set"

  dynamic "sql_injection_match_tuple" {
    iterator = x
    for_each = var.sqli_request_fields
    content {
      text_transformation = "HTML_ENTITY_DECODE"
      field_to_match {
        type = x.value
      }
    }
  }
  dynamic "sql_injection_match_tuple" {
    iterator = x
    for_each = var.sqli_request_fields
    content {
      text_transformation = "URL_DECODE"
      field_to_match {
        type = x.value
      }
    }
  }
  dynamic "sql_injection_match_tuple" {
    iterator = x
    for_each = var.sqli_request_headers
    content {
      text_transformation = "HTML_ENTITY_DECODE"
      field_to_match {
        type = "HEADER"
        data = x.value
      }
    }
  }
  dynamic "sql_injection_match_tuple" {
    iterator = x
    for_each = var.sqli_request_headers
    content {
      text_transformation = "URL_DECODE"
      field_to_match {
        type = "HEADER"
        data = x.value
      }
    }
  }
}

# OWASP - A2 
resource "aws_wafregional_rule" "detect_bad_auth_token" {
  name        = "${var.waf_name}_bad_auth_token"
  metric_name = "${var.waf_name}BadAuthToken"

  predicate {
    data_id = aws_wafregional_byte_match_set.bad_auth_match_set.id
    negated = false
    type    = "ByteMatch"
  }
}

resource "aws_wafregional_byte_match_set" "bad_auth_match_set" {
  name = "${var.waf_name}_bad_auth_match_set"

  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.auth_tokens_black_list
    content {
      text_transformation   = "HTML_ENTITY_DECODE"
      target_string         = x.value
      positional_constraint = "CONTAINS"
      field_to_match {
        type = "HEADER"
        data = "Authorization"
      }
    }
  }

  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.auth_tokens_black_list
    content {
      text_transformation   = "HTML_ENTITY_DECODE"
      target_string         = x.value
      positional_constraint = "CONTAINS"
      field_to_match {
        type = "HEADER"
        data = "Cookie"
      }
    }
  }
  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.auth_tokens_black_list
    content {
      text_transformation   = "URL_DECODE"
      target_string         = x.value
      positional_constraint = "CONTAINS"
      field_to_match {
        type = "HEADER"
        data = "Authorization"
      }
    }
  }
  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.auth_tokens_black_list
    content {
      text_transformation   = "URL_DECODE"
      target_string         = x.value
      positional_constraint = "CONTAINS"
      field_to_match {
        type = "HEADER"
        data = "Cookie"
      }
    }
  }
}

# Block IP after certain number of attempts
resource "aws_wafregional_rate_based_rule" "block_ip_failling_login" {
  name        = "${var.waf_name}_block_ip"
  metric_name = "${var.waf_name}BlockIp"

  rate_key   = "IP"
  rate_limit = 100

  predicate {
    data_id = aws_wafregional_byte_match_set.login_failures.id
    negated = false
    type    = "ByteMatch"
  }
}
resource "aws_wafregional_byte_match_set" "login_failures" {
  name = "${var.waf_name}_login_failures"

  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.login_request
    content {
      text_transformation   = "URL_DECODE"
      target_string         = x.value
      positional_constraint = "STARTS_WITH"
      field_to_match {
        type = "URI"
      }
    }
  }
  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.login_request
    content {
      text_transformation   = "HTML_ENTITY_DECODE"
      target_string         = x.value
      positional_constraint = "STARTS_WITH"
      field_to_match {
        type = "URI"
      }
    }
  }    
}

# OWASP - A3 
resource "aws_wafregional_rule" "xss_mitigation" {
  name        = "${var.waf_name}_xss_mitigation"
  metric_name = "${var.waf_name}XssMitigation"

  predicate {
    data_id = aws_wafregional_xss_match_set.xss_match_set.id
    negated = false
    type    = "XssMatch"

  }
}
resource "aws_wafregional_xss_match_set" "xss_match_set" {
  name  = "${var.waf_name}_xss_match_set"

  dynamic "xss_match_tuple" {
    iterator = x
    for_each = var.xss_request_fields
    content {
      text_transformation = "HTML_ENTITY_DECODE"
      field_to_match {
        type = x.value
      }
    }
  }
  dynamic "xss_match_tuple" {
    iterator = x
    for_each = var.xss_request_fields
    content {
      text_transformation = "URL_DECODE"
      field_to_match {
        type = x.value
      }
    }
  }
  dynamic "xss_match_tuple" {
    iterator = x
    for_each = var.xss_request_headers
    content {
      text_transformation = "HTML_ENTITY_DECODE"
      field_to_match {
        type = "HEADER"
        data = x.value
      }
    }
  }
  dynamic "xss_match_tuple" {
    iterator = x
    for_each = var.xss_request_headers
    content {
      text_transformation = "URL_DECODE"
      field_to_match {
        type = "HEADER"
        data = x.value
      }
    }
  }
}

# OWASP - A4
resource "aws_wafregional_rule" "detect_rfi_lfi_traversal" {
  name        = "${var.waf_name}_detect_rfi_lfi_traversal"
  metric_name = "${var.waf_name}DetectRfiLfiTraversal"

  predicate {
    data_id = aws_wafregional_byte_match_set.rfi_lfi_traversal_match_set.id
    negated = false
    type    = "ByteMatch"
  }
}
resource "aws_wafregional_byte_match_set" "rfi_lfi_traversal_match_set" {
  name  = "${var.waf_name}_rfi_lfi_traversal_match_set"

  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.rfi_lfi_querystring
    content {
      text_transformation   = "HTML_ENTITY_DECODE"
      target_string         = x.value
      positional_constraint = "CONTAINS"
      field_to_match {
        type = "QUERY_STRING"
      }
    }
  }
  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.rfi_lfi_querystring
    content {
      text_transformation   = "URL_DECODE"
      target_string         = x.value
      positional_constraint = "CONTAINS"
      field_to_match {
        type = "QUERY_STRING"
      }
    }
  }
  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.rfi_lfi_uri
    content {
      text_transformation   = "HTML_ENTITY_DECODE"
      target_string         = x.value
      positional_constraint = "CONTAINS"
      field_to_match {
        type = "QUERY_STRING"
      }
    }
  }
  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.rfi_lfi_uri
    content {
      text_transformation   = "URL_DECODE"
      target_string         = x.value
      positional_constraint = "CONTAINS"
      field_to_match {
        type = "QUERY_STRING"
      }
    }
  }
}

# OWASP - A7
resource "aws_wafregional_rule" "restrict_sizes" {
  name        = "${var.waf_name}_restrict_sizes"
  metric_name = "${var.waf_name}RestrictSizes"

  predicate {
    data_id = aws_wafregional_size_constraint_set.size_restrictions_match.id
    negated = false
    type    = "SizeConstraint"
  }
}

resource "aws_wafregional_size_constraint_set" "size_restrictions_match" {
  name  = "${var.waf_name}_size_restrictions_match"

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = var.max_expected_uri_size

    field_to_match {
      type = "URI"
    }
  }

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = var.max_expected_query_string_size

    field_to_match {
      type = "QUERY_STRING"
    }
  }

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = var.max_expected_body_size

    field_to_match {
      type = "BODY"
    }
  }

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "GT"
    size                = var.max_expected_cookie_size

    field_to_match {
      type = "HEADER"
      data = "cookie"
    }
  }

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "LT"
    size                = var.min_expected_x_api_key_size

    field_to_match {
      type = "HEADER"
      data = "x-api-key"
    }
  }
}

# OWASP - A8
resource "aws_wafregional_rule" "enforce_csrf" {
  name        = "${var.waf_name}_enforce_csrf"
  metric_name = "${var.waf_name}EnforceCsrf"
  
  predicate {
    data_id = aws_wafregional_byte_match_set.csrf_method_match.id
    negated = false
    type    = "ByteMatch"
  }

  predicate {
    data_id = aws_wafregional_size_constraint_set.csrf_token_match.id
    negated = true
    type    = "SizeConstraint"
  }
}

resource "aws_wafregional_byte_match_set" "csrf_method_match" {
  name  = "${var.waf_name}_csrf_method_match"

  byte_match_tuples {
    text_transformation   = "LOWERCASE"
    target_string         = "post"
    positional_constraint = "EXACTLY"

    field_to_match {
      type = "METHOD"
    }
  }
}

resource "aws_wafregional_size_constraint_set" "csrf_token_match" {
  name  = "${var.waf_name}_csrf_token_match"

  size_constraints {
    text_transformation = "NONE"
    comparison_operator = "EQ"
    size                = var.csrf_size

    field_to_match {
      type = "HEADER"
      data = var.csrf_header
    }
  }
}

# 0WASP - RULE 9
resource "aws_wafregional_rule" "detect_ssi" {
  name        = "${var.waf_name}_detect_ssi"
  metric_name = "${var.waf_name}DetectSsi"

  predicate {
    data_id   = aws_wafregional_byte_match_set.ssi_sizes_match.id
    negated   = false
    type      = "ByteMatch"
  }
}
resource "aws_wafregional_byte_match_set" "ssi_sizes_match" {
  name       = "${var.waf_name}_ssi_sizes_match"

  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.ssi_file_extensions

    content {
      text_transformation   = "LOWERCASE"
      target_string         = lower(x.value)
      positional_constraint = "ENDS_WITH"

      field_to_match {
        type = "URI"
      }
    }
  }
  dynamic "byte_match_tuples" {
    iterator = x
    for_each = var.ssi_paths

    content {
      text_transformation   = "URL_DECODE"
      target_string         = x.value
      positional_constraint = "STARTS_WITH"

      field_to_match {
        type = "URI"
      }
    }
  }
}

