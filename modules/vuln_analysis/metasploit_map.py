METASPLOIT_CHECK_MAP = {
    "ftp": {
        "vsftpd 2.3.4": "exploit/unix/ftp/vsftpd_234_backdoor"
    },
    "http": {
        "apache 2.2": "exploit/multi/http/apache_mod_cgi_bash_env_exec"
    },
    "ssh": {
        "user_enumeration": "auxiliary/scanner/ssh/ssh_enumusers"
    }
}
