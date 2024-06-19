# Nftables parental control

Simple application that allows to add and remove rules to nftables using REST APIs.

> [!warning]
> The software can delete and create rules on the host, this means that you can potentially lock yourself out of the system. Also, the application does not have any access control system or any form of authentication. Use at your own risk.

## Run the application

```bash
sudo go run main.go
```

## Compile the application

```bash
go build -o build/npc main.go
```
