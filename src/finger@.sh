host=${1-0}
user=${2-}
port=79
echo "$user" | HOME/bin/tcpclient -RHl0 -- "$host" "$port" sh -c '
  HOME/bin/addcr >&7
  exec HOME/bin/delcr <&6
' | cat -v
