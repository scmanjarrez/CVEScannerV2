FROM str0ke/nmap
RUN apk add --no-cache lua5.4-sql-sqlite3 && ln -s /usr/lib/lua /usr/local/lib/lua
COPY extra /CVEScannerV2/extra
COPY cvescannerv2.nse /CVEScannerV2
WORKDIR /CVEScannerV2
ENTRYPOINT ["nmap", "--script", "cvescannerv2", "-sV"]
