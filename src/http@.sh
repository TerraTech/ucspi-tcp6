host=${1-0}
path=${2-}
port=${3-80}
echo "GET /${path} HTTP/1.0
Host: [${host}]:${port}
" | HOME/bin/tcpclient -RHl0 -- "$host" "$port" sh -c '
  HOME/bin/addcr >&7
  exec HOME/bin/delcr <&6
' | awk '/^$/ { body=1; next } { if (body) print }'
