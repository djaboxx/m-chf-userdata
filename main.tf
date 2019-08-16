# Render a part using a `template_file`
data "template_file" "aws_script" {
  template = file("${path.module}/scripts/init.tpl")

  vars {
    chef_config_bucket    = "${var.chef_config_bucket}"
    chef_config_path      = "${var.chef_config_path}"
    chef_frontend_version = "${var.chef_frontend["version"]}"
    chef_backend_version  = "${var.chef_backend["version"]}"
    auth_cidr             = "${var.auth_cidr_addresses}"
    node_name             = "${var.node_name}"
    install_chef_manage   = "${var.install_chef_manage ? "-m" : ""}"
    chef_org              = "${var.chef_org}"
    chef_admin_email      = "${var.chef_admin_email}"
    chef_admin_password   = "${random_string.password.result}"
    chef_config_script    = "${var.chef_config_script}"
    chef_automate_token   = "${var.chef_automate_token}"
    chef_automate_host    = "${var.chef_automate_host}"
    network_option        = "${var.network_option}"
  }
}
