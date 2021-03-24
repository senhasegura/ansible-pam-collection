## senhasegura_credential

This module can be used to create, update and deactivate credentials in senhasegura's PAM module

---

### Example PlayBooks

Ensure credential 'ansible' in device 'linux-001'

```yaml
- name: Ensure credential 'ansible' in device 'linux-001'
  senhasegura.pam.senhasegura_credential:
    state: present
    identifier: ansible-usr-linux-001
    device_hostname: linux-001
    type: Local user
    username: ansible
    password: your_secret_password
    tags:
      - ansible
      - automation
    additional_info: 'Credential created by Ansible'
```

Domain user CORP\bob creation in senhasegura

```yaml
- name: Ensure domain user 'CORP\bob' in device 'windows-ad'
  senhasegura.pam.senhasegura_credential:
    state: present
    identifier: your_unique_credential_identifier
    device_hostname: windows-ad
    type: Domain user
    username: ansible
    password: your_secret_password
    domain: CORP
    tags:
      - domain
      - automation
    additional_info: 'Credential created by Ansible'
```

Deactivate credential with identifier "domain_user_alice"

```yaml
- name: Deactivate credential
  senhasegura.pam.senhasegura_credential:
    state: absent
    identifier: domain_user_alice
```
---

### Available options

```
options:
    system_url:
        type: str
        description:
            - senhasegura's environment URL used for authentication, SENHASEGURA_URL environment variable may also be used
    client_id:
        type: str
        description:
            - A2A OAuth2 client_id, SENHASEGURA_CLIENT_ID environment variable may also be used
    client_secret:
        type: str
        description:
            - A2A OAuth2 client_secret, SENHASEGURA_CLIENT_SECRET environment variable may also be used
    state:
        description:
            - Whether the credential should exist or not,
        type: str
        choices: [ absent, present ]
        default: present
    identifier:
        required: true
        type: str
        description:
            - credential identifier for management
    device_hostname:
        type: str
        description:
            - Device hostname to link credential
            - Required when state is present
    device_address:
        type: str
        description:
            - Device address to link credential
            - Required when state is present
    type:
        description:
            - Type of credential
            - Required when state is present
        type: str
        choices: [ Local User, Local administrator, Domain user ]
        default: Local User
    username:
        type: str
        description:
            - Credential username
            - Required when state is present
    password:
        description:
            - Credential password
            - This password must meet the password policy requirements
        type: str
    domain:
        description:
            - Domain name, It needs to be previously registered in senhasegura
        type: str
    tags:
        description:
            - Credential tags
        type: list
    additional_info:
        description:
            - Credential additional information
        type: str
    parent_credential:
        description:
            - Parent credential numeric identifier
        type: int
    validate_certs:
        description:
            - Whether to validate or not the HTTPS certificate
        type: boolean
```

---

Full module docummentation is available using `ansible-doc` after collection install

    $ ansible-galaxy collection install senhasegura.pam
    $ ansible-doc --type module senhasegura.pam.senhasegura_credential

