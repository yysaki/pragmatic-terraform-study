# chapter 3

module "web_server" {
  source        = "./http_server"
  instance_type = "t3.micro"
}

output "public_dns" {
  value = module.web_server.public_dns
}

terraform {
  required_version = "0.12.5"
}
