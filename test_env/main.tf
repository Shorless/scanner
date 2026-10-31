resource "tls_private_key" "jwt_Step_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "aws_lb_listener" "https" {
  port       = 443
  protocol   = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-2016-08"
}
