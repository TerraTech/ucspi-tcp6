host=${1-0}
port=11
HOME/bin/tcpclient -RHl0 -- "$host" "$port" sh -c 'exec HOME/bin/delcr <&6' | cat -v
