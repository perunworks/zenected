VAGRANTFILE_API_VERSION = "2"

vm_group = "/test"

vm_boxes = {
  "zenected" => {
    "ip" => "192.168.1.254",
    "ports" => {
      "http" => {
        "host" => 8080,
        "guest" => 80,
        "protocol" => "tcp"
      },
      "https" => {
        "host" => 8443,
        "guest" => 443,
        "protocol" => "tcp"
      },
      "ipsec1" => {
        "host" => 8500,
        "guest" => 500,
        "protocol" => "udp"
      },
      "ipsec2" => {
        "host" => 4500,
        "guest" => 4500,
        "protocol" => "udp"
      },
    }
  },
}

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "ubuntu/trusty64"
  # config.ssh.insert_key = false

  vm_boxes.each do |name, box|
    config.vm.define "#{name}" do |node|
      node.vm.hostname = "#{name}"
      node.vm.network :private_network, ip: box["ip"], netmask: "255.255.255.0"
      box["ports"].each do |id, ports|
        node.vm.network :forwarded_port, guest: ports["guest"], host: ports["host"], id: id
      end

      node.vm.provider "virtualbox" do |v|
        v.memory = 1024
        v.name = "#{name}"
        v.customize [
          "modifyvm", :id,
          "--groups", vm_group
        ]
      end
    end
  end
end
