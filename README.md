# pdns-recursor-filter
LUA script(s) that can filter & redirect queries sent to PowerDNS Recursor.

# Install
* Add lua-dns-script= to recursor.conf
* Change ipv4_redirect_host in LUA script

# ToDo
* IPv6 / AAAA checking
* Improved search, in-memory index, SQLite or REDIS?
