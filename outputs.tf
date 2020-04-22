output "alb_dns_name" {
  value       = aws_lb.example.dns_name
  description = "The DNS name of ALB."
}

output "domain_name" {
  value       = aws_route53_record.example.name
  description = "The domain name of Route53 record."
}

output "codepipeline_webhook_url" {
  value       = aws_codepipeline_webhook.example.url
  description = "The webhook url of codepipeline for github push"
}

output "operation_instance_id" {
  value       = aws_instance.example_for_operation.id
  description = "The ID of EC2 instance for SSH-less operation."
}
