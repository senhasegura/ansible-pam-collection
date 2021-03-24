![logo](https://github.com/senhasegura/ansible-pam-collection/blob/main/docs/imgs/senhasegura-logo.jpg?raw=true)


## senhasegura Privileged Access Management Ansible Collection

senhasegura PAM Ansible Collection provides ansible modules for interacting with senhasegura's PAM module

Hosted in [galaxy.ansible.com/senhasegura](https://galaxy.ansible.com/senhasegura)

*************

### Requirements

  - senhasegura with PAM module enabled

---

### Installation

In your terminal, run the following command

	ansible-galaxy collection install senhasegura.pam

### Modules

**senhasegura_device**

With this module you can create, update and deactivate devices in senhasegura's PAM module

[Detailed documentation](https://github.com/senhasegura/ansible-pam-collection/blob/main/docs/senhasegura_device.md)

**senhasegura_credential**

With this module you can create, update and deactivate credentials in senhasegura's PAM module

[Detailed documentation](https://github.com/senhasegura/ansible-pam-collection/blob/main/docs/senhasegura_credential.md)

**senhasegura_credential_info**

With this module you can get informations about a credential, including your password

[Detailed documentation](https://github.com/senhasegura/ansible-pam-collection/blob/main/docs/senhasegura_credential_info.md)

---

## Author information

- Lucas Fraga (@lfraga)
- James Miranda (@jameswpm)

