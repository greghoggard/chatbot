provider "aws" {
  region = "us-east-1"
}

# Existing VPC and Subnets
data "aws_vpc" "existing_vpc" {
  id = "vpc-083b2372ea55749a4"
}

data "aws_subnet" "public_subnet" {
  id = "subnet-0b9a2fd0bebdce70e"
}

data "aws_subnet" "private_subnet_1" {
  id = "subnet-03acac5efa3ed39e6"
}

data "aws_subnet" "private_subnet_2" {
  id = "subnet-0c6d45ee5ab4e80f2"
}

data "aws_subnet" "isolated_subnet" {
  id = "subnet-0c8c946f1501d8bd1"
}

# Security Group for Bastion Host (SSH Access)
resource "aws_security_group" "bastion_sg" {
  name        = "bastion_sg"
  description = "Allow SSH access to Bastion Host"
  vpc_id      = "vpc-083b2372ea55749a4"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Your local machine IP for SSH access
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Security Group for EC2 instance in private subnet
resource "aws_security_group" "private_instance_sg" {
  name        = "private_instance_sg"
  description = "Allow internal communication between Bastion and Private instance"
  vpc_id      = "vpc-083b2372ea55749a4"

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion_sg.id] # Allow SSH from Bastion Host
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Bastion Host in public subnet
resource "aws_instance" "bastion" {
  ami                         = "ami-0866a3c8686eaeeba" # Replace with a valid AMI
  instance_type               = "t3.medium"
  key_name                    = "my-key-pair"
  subnet_id                   = "subnet-0b9a2fd0bebdce70e" # Public subnet
  associate_public_ip_address = true
  vpc_security_group_ids = [aws_security_group.bastion_sg.id]

  tags = {
    Name = "BastionHost"
  }
}

# IAM Role and Policy for EC2 Instance
resource "aws_iam_role" "ec2_role" {
  name = "ec2_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_policy" "appsync_policy" {
  name        = "AppSyncAccessPolicy"
  description = "Custom policy for AppSync access"
  
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "appsync:*",
          "iam:PassRole"
        ],
        Effect   = "Allow",
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "appsync_access" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.appsync_policy.arn
}


resource "aws_iam_role_policy_attachment" "route53_access" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonRoute53FullAccess"
}

resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "ec2_instance_profile"
  role = aws_iam_role.ec2_role.name
}

# NAT Gateway Route Table association for private subnet
resource "aws_route_table_association" "private_subnet_route" {
  subnet_id      = "subnet-03acac5efa3ed39e6"
  route_table_id = "rtb-09aca1aa11bb84edf"  # Private Route Table with NAT gateway
}

# Create the EC2 instance in your private subnet
resource "aws_instance" "appsync_test_instance" {
  ami                    = "ami-0866a3c8686eaeeba" # Use a proper Ubuntu AMI
  instance_type          = "t3.medium"
  subnet_id              = data.aws_subnet.private_subnet_1.id # Place this in one of your private subnets
  vpc_security_group_ids = [aws_security_group.private_instance_sg.id] # Use security group ID instead of name
  key_name               = "my-key-pair"  # Replace with your existing key pair

  iam_instance_profile   = aws_iam_instance_profile.ec2_instance_profile.id

  tags = {
    Name = "AppSync-Test-Instance"
  }

  # Ensure that the instance has sufficient private DNS resolution
  user_data = <<-EOF
                #!/bin/bash
                apt update
                apt install -y awscli
                echo "export AWS_DEFAULT_REGION=us-east-1" >> /home/ubuntu/.bashrc
                EOF
}

output "bastion_public_ip" {
  value = aws_instance.bastion.public_ip
}

output "private_instance_id" {
  value = aws_instance.appsync_test_instance.id
}

# Security group rule to allow the EC2 instance to communicate with AppSync in the VPC
resource "aws_security_group_rule" "appsync_allow_vpc" {
  security_group_id = aws_security_group.private_instance_sg.id
  type = "egress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["10.37.58.0/24"] # Adjust this CIDR block based on your VPC range
}

# Route53 Private Hosted Zone
resource "aws_route53_zone" "private_zone" {
  name = "gpnlabs-test.com"
  vpc {
    vpc_id = data.aws_vpc.existing_vpc.id
  }
}

# ACM Certificate for AppSync API
resource "aws_acm_certificate" "appsync_cert" {
  domain_name       = "appsync.gpnlabs-test.com"
  validation_method = "DNS"
  tags = {
    Name = "AppSyncCert"
  }

  validation_option {
    domain_name       = "appsync.gpnlabs-test.com"
    validation_domain = "gpnlabs-test.com"
  }
}

# ACM Validation Record in Route 53
resource "aws_route53_record" "validation_record" {
  for_each = { for dvo in aws_acm_certificate.appsync_cert.domain_validation_options : dvo.domain_name => dvo }

  zone_id = aws_route53_zone.private_zone.zone_id
  name    = each.value.resource_record_name
  type    = each.value.resource_record_type
  records = [each.value.resource_record_value]
  ttl     = 60
}

# Private AppSync API
resource "aws_appsync_graphql_api" "private_appsync" {
  name                = "ChatBotPrivateApi"
  authentication_type = "AWS_IAM"
  xray_enabled        = true
  visibility          = "PRIVATE"
}

# VPC Endpoint for AppSync
resource "aws_vpc_endpoint" "appsync_endpoint" {
  vpc_id            = data.aws_vpc.existing_vpc.id
  service_name      = "com.amazonaws.us-east-1.appsync-api"
  vpc_endpoint_type = "Interface"
  subnet_ids        = [
    data.aws_subnet.private_subnet_1.id, 
    data.aws_subnet.private_subnet_2.id, 
    data.aws_subnet.public_subnet.id
  ]
  private_dns_enabled = true
}

# VPC Endpoint for S3
# resource "aws_vpc_endpoint" "s3_endpoint" {
#   vpc_id       = data.aws_vpc.existing_vpc.id
#   vpc_endpoint_type = "Gateway"
#   service_name = "com.amazonaws.us-east-1.s3"
#   route_table_ids = ["rtb-09aca1aa11bb84edf"]
# }

# Output the AppSync endpoint and ALB DNS name
output "appsync_api_endpoint" {
  value = aws_appsync_graphql_api.private_appsync.uris["GRAPHQL"]
}