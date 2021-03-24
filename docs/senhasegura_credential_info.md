## senhasegura_credential_info

This module can be used to get credentials information and secret strings a.k.a passwords

---

### Example PlayBooks


Get credential by identifier

```yaml
- name: Get credential with identifier 'ansible
  senhasegura.pam.senhasegura_credential_info:
    identifier: your_credential_identifier
  register: senhasegura_credential
```

Get credential by ID
```yaml
- name: Get credential with identifier 'ansible
  senhasegura.pam.senhasegura_credential_info:
    id_credential: 1582
  register: senhasegura_credential
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
    identifier:
        type: str
        description:
            - The credential identifier to get information
    id_credential:
        type: str
        description:
            - The credential ID to get information
    validate_certs:
        description:
            - Whether to validate or not the HTTPS certificate
        type: bool
```

---

Full module docummentation is available using `ansible-doc` after collection install

    $ ansible-galaxy collection install senhasegura.pam
    $ ansible-doc --type module senhasegura.pam.senhasegura_credential_info

