resource "aws_wafregional_web_acl" "waf_acl" {
  name        = var.waf_name
  metric_name = var.waf_name

  default_action {
    type = "ALLOW"
  }

  # Block incoming traffic according to the country of origin
  rule {
    action {
      type = var.rule_action
    }
    priority = var.rule_priority
    rule_id  = aws_wafregional_rule.country_of_origin_filter.id
    type     = "REGULAR"
  }  

  # Mitigate SQL injection attacks
  rule {
    action {
      type = var.sqli_action
    }

    priority = var.sqli_priority
    rule_id  = aws_wafregional_rule.sqli_mitigation.id
    type     = "REGULAR"
  }

  # Detect Bad Authentication tokens
  rule {
    action {
      type = var.bad_auth_token_action
    }

    priority = var.bad_auth_token_priority
    rule_id  = aws_wafregional_rule.detect_bad_auth_token.id
    type     = "REGULAR"
  }

  # Block IPs which exceed login attempts
  rule {
    action {
      type = var.block_ip_login_exceeds_action
    }

    priority = var.block_ip_login_exceeds_priority
    rule_id  = aws_wafregional_rate_based_rule.block_ip_failling_login.id
    type     = "RATE_BASED"
  }

  # Mitigate Cross Site Scripting
  rule {
    action {
      type = var.xss_action
    }
    
    priority = var.xss_priority
    rule_id  = aws_wafregional_rule.xss_mitigation.id
    type     = "REGULAR"
  }

  # path traversal (rfi-lfi)
  rule {
    action {
      type = var.rfi_lfi_action
    }
    
    priority = var.rfi_lfi_priority
    rule_id  = aws_wafregional_rule.detect_rfi_lfi_traversal.id
    type     = "REGULAR"
	}

  # size constraints
  rule {
    action {
      type = var.size_constraints_action
    }

    priority = var.size_constraints_priority
    rule_id  = aws_wafregional_rule.restrict_sizes.id
    type     = "REGULAR"
  }

  # csrf - cross site request forgery
  rule {
    action {
      type = var.csrf_action
    }

    priority = var.csrf_priority
    rule_id  = aws_wafregional_rule.enforce_csrf.id
    type     = "REGULAR"
  }
  # ssi - server-side includes
  rule {
    action {
      type = var.ssi_action
    }

    priority = var.ssi_priority
    rule_id  = aws_wafregional_rule.detect_ssi.id
    type     = "REGULAR"
  }
}

resource "aws_wafregional_web_acl_association" "acl_alb_association" {
  depends_on = [
    aws_wafregional_web_acl.waf_acl
  ]
  resource_arn = var.alb_arn
  web_acl_id   = aws_wafregional_web_acl.waf_acl.id
}
