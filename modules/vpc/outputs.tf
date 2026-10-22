output "vpc_id" {
  description = "ID of the VPC."
  value       = aws_vpc.this.id
}

output "cidr_block" {
  description = "CIDR of the VPC."
  value       = aws_vpc.this.cidr_block
}

output "private_subnet_ids" {
  description = "Private subnet IDs, in the order of var.azs."
  value       = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  description = "Public subnet IDs, in the order of var.azs."
  value       = aws_subnet.public[*].id
}

output "flow_log_group_name" {
  description = "CloudWatch log group receiving VPC flow logs."
  value       = aws_cloudwatch_log_group.flow_logs.name
}
