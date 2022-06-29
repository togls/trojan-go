# trojan-go
implement [trojan protocol](https://trojan-gfw.github.io/trojan/protocol) in golang

- run type
  - [x] server
  - [ ] client
  - [ ] forward
- relay
  - [x] tcp
  - [ ] udp
- autocert
  - [x] ZeroSSL with cf DNS 
- other
  - [x] website
  
## docker compose
```yaml
version: '3'
services:
  trojan:
    image: ghcr.io/togls/trojan-go:master
    ports:
      - 443:443
    volumes:
      - certs:/root/.local/share
      - /path/to/site:/var/www/site
      - /path/to/config.json:/etc/trojan-go/config.json
volumes:
  certs:
```
