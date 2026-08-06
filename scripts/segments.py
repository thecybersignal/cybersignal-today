"""
Stack archetypes. This is the file you will edit most often.

Each segment matches a CVE if any keyword appears in the vendor/product
strings NVD publishes (CPE data), or in the vulnerability description.

Keep keywords lowercase. Prefer specific product names over vendor names
where you can -- "fortios" matches better than "fortinet", which also
catches unrelated Fortinet products.
"""

SEGMENTS = {
    "edge-vpn": {
        "label": "Edge & remote access",
        "blurb": "VPN concentrators, SSL gateways, and anything you publish to the internet.",
        "keywords": [
            "ivanti", "connect_secure", "pulse_secure", "citrix", "netscaler",
            "fortinet", "fortios", "fortigate", "palo_alto", "pan-os", "pan_os",
            "sonicwall", "cisco_asa", "adaptive_security_appliance", "globalprotect",
        ],
    },
    "microsoft-smb": {
        "label": "Microsoft-first shop",
        "blurb": "Windows Server, Exchange, Entra, and the Microsoft 365 estate.",
        "keywords": [
            "microsoft", "windows_server", "exchange_server", "sharepoint",
            "active_directory", "entra", "azure", "office", "outlook", "hyper-v",
        ],
    },
    "virtualization": {
        "label": "Virtualization & hypervisor",
        "blurb": "VMware, Proxmox, and the layer everything else runs on.",
        "keywords": [
            "vmware", "vcenter", "esxi", "vsphere", "workstation_pro",
            "proxmox", "nutanix", "xenserver",
        ],
    },
    "backup": {
        "label": "Backup & recovery",
        "blurb": "The systems ransomware crews hit before they encrypt anything.",
        "keywords": [
            "veeam", "commvault", "acronis", "rubrik", "veritas", "backup_exec",
            "networker", "arcserve",
        ],
    },
    "msp-fleet": {
        "label": "MSP tooling",
        "blurb": "RMM and remote-support platforms with reach into every client.",
        "keywords": [
            "connectwise", "screenconnect", "kaseya", "datto", "n-able", "n_able",
            "ninjaone", "solarwinds", "atera", "anydesk", "teamviewer",
        ],
    },
    "file-transfer": {
        "label": "Managed file transfer",
        "blurb": "The category with the worst mass-extortion track record in the business.",
        "keywords": [
            "moveit", "goanywhere", "cleo", "fortra", "filezilla",
            "serv-u", "serv_u", "crushftp", "aspera",
        ],
    },
    "devstack": {
        "label": "Developer & collaboration stack",
        "blurb": "Confluence, Jenkins, GitLab, and the internal tools nobody patches.",
        "keywords": [
            "atlassian", "confluence", "jira", "bitbucket", "jenkins",
            "gitlab", "sonarqube", "nexus_repository", "wordpress",
        ],
    },
}

# Anything at or above this score is shown above the fold on the page.
CUTLINE = 60

# How many items to keep per segment in the published JSON.
ITEMS_PER_SEGMENT = 12
