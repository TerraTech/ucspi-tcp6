host=${1-0}
port=${2-17}
exec HOME/bin/tcpclient -RHl0 -- "$host" "$port" sh -c 'exec cat <&6'
