variable "chef_config_script" {}
variable "chef_config_bucket" {}
variable "chef_config_path" {}
variable "chef_frontend_version" {}
variable "chef_backend_version" {}
variable "auth_cidr" {}
variable "node_name" {}
variable "install_chef_manage" {}
variable "chef_org" {}
variable "chef_admin_email" {}
variable "chef_admin_password" {}
variable "chef_automate_token" {}
variable "chef_automate_host" {}
varriable "network_option" {
    description = "Specify -a for AWS, -d for a specific ip, or -i for the ip of the current node"
}
