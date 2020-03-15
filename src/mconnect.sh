host=${1-0}
port=${2-25}
exec HOME/bin/tcpclient -RHl0 -- "$host" "$port" HOME/bin/mconnect-io
