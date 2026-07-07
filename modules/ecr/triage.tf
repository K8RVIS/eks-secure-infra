# ---------------------------------------------------------------------------
# Inspector v2 finding triage — suppress findings irrelevant to each service
#
# AWS Inspector surfaces ALL CVEs found in a container image, including
# vulnerabilities in package ecosystems that the service never executes
# (e.g., a PHP CVE in an nginx image). These false-positives create alert
# fatigue and obscure genuinely actionable findings.
#
# Each aws_inspector2_filter below targets one ECR repository and suppresses
# findings whose vulnerable package name matches an ecosystem unrelated to
# that service's runtime. Only findings for packages the service actually
# loads remain ACTIVE and flow through EventBridge → SNS.
#
# Suppressed findings are still stored in Inspector; they are hidden from
# the active findings list and will not trigger alerts.
# ---------------------------------------------------------------------------

resource "aws_inspector2_filter" "triage" {
  for_each = var.triage_suppressions

  name        = "${var.project_name}-triage-${each.key}"
  action      = "SUPPRESS"
  description = each.value.reason

  filter_criteria {
    # Scope this suppression to a single repository
    ecr_image_repository_name {
      comparison = "EQUALS"
      value      = "${var.project_name}/${each.key}"
    }

    # Each package_name entry becomes an OR condition — suppress a finding
    # if the vulnerable package name starts with ANY of the listed prefixes.
    dynamic "vulnerable_packages" {
      for_each = each.value.package_names
      content {
        name {
          comparison = "PREFIX"
          value      = vulnerable_packages.value
        }
      }
    }
  }

  tags = merge(local.common_tags, {
    Name      = "${var.project_name}-triage-${each.key}"
    TriageFor = each.key
  })

  depends_on = [aws_inspector2_enabler.ecr]
}
