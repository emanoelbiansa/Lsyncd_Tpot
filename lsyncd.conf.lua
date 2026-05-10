settings {
    logfile = "/var/log/lsyncd/lsyncd.log",
    statusFile = "/var/log/lsyncd/lsyncd.status",
    statusInterval = 20,
    insist = true
}

sync {
    default.rsyncssh,
    source = "/home/emanuel/tpotce/data",
    host = "user@ip",
    targetdir = "/home/user/honeypot_logs/tpot_data",
    delete = "running",
    delay = 5,
    rsync = {
        archive = true,
        compress = true,
    }
}
