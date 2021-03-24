## senhasegura_device

This module can be used to create, update and deactivate devices in senhasegura's PAM module

---

### Example PlayBooks

Ensure device with hostname linux-001 and address 172.30.54.10

```yaml
- name: Ensure device linux-001
  senhasegura.pam.senhasegura_device:
    state: present
    address: 172.30.54.10
    connectivities: ["SSH:22"]
    hostname: linux-001
    type: Server
    vendor: Red Hat
    model: Red Hat Enterprise Linux
    site: AWS
    tags:
      - aws
      - linux
```

Deactivate device windows-001

```yaml
- name: Absent device windows-001
  senhasegura.pam.senhasegura_device:
    state: absent
    address: 172.30.54.20
    hostname: windows-001
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
            - Whether the device should exist or not,
        type: str
        choices: [ absent, present ]
        default: present
    hostname:
        required: true
        type: str
        description:
            - Hostname of device
    address:
        required: true
        type: str
        description: IP or DNS
    type:
        description:
            - Type of device, if non-existent, will be created.
            - Required when state is present
        type: str
    vendor:
        description:
            - Vendor of device, if non-existent, will be created.
            - Required when state is present
        type: str
    model:
        description:
            - Model of device, if non-existent, will be created.
            - Required when state is present
        type: str
    site:
        description:
            - Site of device.
            - Required when state is present
        type: str
    domain:
        description:
            - The device domain.
        type: str
    connectivities:
        description:
            - The connectivity protocols on device in format <Protocol>:<Port>
            - Example 'SSH:22'
        type: list
    tags:
        description:
            - The device tags.
        type: list
    validate_certs:
        description:
            - Whether to validate or not the HTTPS certificate
        type: boolean
```

---

Full module docummentation is available using `ansible-doc` after collection install

    $ ansible-galaxy collection install senhasegura.pam
    $ ansible-doc --type module senhasegura.pam.senhasegura_device

