target_sources(bof-archive PRIVATE
    dsrcli.cpp
    dump_credential_key.cpp
    get_device_sso_cookie.cpp
    get_ntlmv1_response.cpp
    get_pop_token.cpp
    get_sso_cookie.cpp
    list_logon_sessions.cpp
    load_ssp.cpp
    purge_tickets.cpp
    show_cloud_config.cpp
    show_domain_config.cpp
    show_kerberos_config.cpp
    transfer_creds.cpp
    whoami.cpp
)