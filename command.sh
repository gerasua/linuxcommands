#Last update Complete date 
sudo rpm -qa --last | grep -i kernel | grep -v "dev" | grep -v "headers" | grep -v "tools" | head -1 | awk '{print $2, $3, $4, $5, $6, $7, $8}'
# Simple Date 
sudo rpm -qa --last | grep -i kernel | grep -v "dev" | grep -v "headers" | grep -v "tools" | head -1 | awk '{print $4, $3, $6, $7, $8}'

# Installed Kernel
sudo rpm -qa --last | grep -i kernel | grep -v "dev" | grep -v "headers" | grep -v "tools" | grep -v "debug" | grep -v "doc" | head -1 | awk '{print $1}';

# Installed Kernel Date
sudo rpm -qa --last | grep -i kernel | grep -v "dev" | grep -v "headers" | grep -v "tools" | grep -v "debug" | grep -v "doc" | head -1 | awk '{print $4, $3, $6, $7, $8}';


#echo Available Kernel
sudo yum list kernel | grep kernel | tail -1 | awk '{print $2}';

# uptime
echo System Uptime;uptime | sed -E 's/^.+([0-9]+ days).+$/\1/';

# yum
yum check-update

yum makecache fast

## Install yum utils ##
yum install yum-utils

# Clean boot partition 
package-cleanup --oldkernels --count=2


# Check yum history
yum history

yum history info 30


#CPU 
while true; do ps -eo ppid,pid,cmd,%mem,%cpu --sort=-%cpu | head; date; echo -e "\n"; sleep 2; done

top -bn2 | grep '%Cpu' | tail -1 | grep -P '(....|...) id,'|awk '{print "CPU Usage: " 100-$8 "%"}'

ps -eo pcpu,pid,user,args | sort -r -k1 | less

ps aux --width 30 --sort -rss | head

cat /proc/stat |grep cpu |tail -1|awk '{print ($5*100)/($2+$3+$4+$5+$6+$7+$8+$9+$10)}'|awk '{print "CPU Usage: " 100-$1}'

ps -Ao user,uid,comm,pid,pcpu,tty --sort=-pcpu | head -n 6

ps -p $PID -o %cpu,%mem

#Memory

top -o +%MEM

vmstat -s -S M | head -10

awk '$3=="kB"{$2=$2/1024^2;$3="GB";} 1' /proc/meminfo | column -t | grep ^Mem

ps -Ao user,uid,comm,pid,pmem,tty --sort=-pmem | head -n 6

free -t | awk 'NR == 2 {printf("Current Memory Utilization is : %.2f%\n%"), $3/$2*100}'

ps aux --width 30 --sort -rss | head

ps aux | awk '{print $2, $4, $11}' | sort -k2r | head -n 15

ps -eo ppid,pid,cmd,%mem,%cpu --sort=-%mem | head

ps -e -orss=,args= | sort -b -k1,1n | pr -TW$COLUMNS

ps -p $PID -o %cpu,%mem

ps aux --sort pmem

# Clear swap and memory

swapoff -a && swapon -a


sync; echo 3 > /proc/sys/vm/drop_caches && swapoff -a && swapon -a && printf '\n%s\n' 'Ram-cache and Swap Cleared'
sync; echo 0 > /proc/sys/vm/drop_caches

OR

su -c "sync; echo 3 >'/proc/sys/vm/drop_caches' && swapoff -a && swapon -a && printf '\n%s\n' 'Ram-cache and Swap Cleared'" root

# Clear Memory cache

sync; echo 1 > /proc/sys/vm/drop_caches

sync; echo 3 > /proc/sys/vm/drop_caches

# We need go back to 0

sync; echo 0 > /proc/sys/vm/drop_caches



### Explicacion ###

echo 0 > /proc/sys/vm/drop_caches 

#Estado normal (no libera nada)

echo 1 > /proc/sys/vm/drop_caches 

#Libera los pagecache

echo 2 > /proc/sys/vm/drop_caches 

#Libera dentries e inodos

echo 3 > /proc/sys/vm/drop_caches 

#Libera pagecache, dentries e inodos (Libera Todo)

#pagecache: Memoria caché de la paginación.
#dentries: (Directory Entries) Representa la relación de forma estructurada que existe entre directorios-archivos.
#inodes: Son nodos índice de archivos y directorios que usa el Sistema de Archivos para administrar las actividades 
#posibles de dichos archivos y directorios guardados en disco o memoria. Contiene la metadata de los archivos y directorios: 
#permisos, tamaño, propietario, última fecha de acceso, creación, modificación, etc…

### Fin explicacion ###

# Last reboots
who -b

last -x | head | tac
 
sudo ausearch -i -m system_boot,system_shutdown | tail -4

journalctl --list-boots

journalctl -b {num} -n

journalctl -b -1 -n

last reboot

grep reboot /home/*/.bash_history

cat /var/log/audit/audit.log | grep reboot

last | grep "Jun 16"

sudo last -Fxn2 shutdown reboot

# Zabbix
systemctl status zabbix-agent.service

#SNMP
systemctl status snmpd.service

# Splunk
service splunk status

# time to be root
time sudo whoami

# Buscar archivos por tamño
find /mnt/nexus -xdev -size +1000M -exec ls -ltrha {} \;

# Biggest directories under the current directory
du -ax . | sort -nr | head -n 10

# Biggest directories in the current working directory
du -a | sort -nr | head -n 5
du -hs * | sort -rh | head -5
du -sk * | sort -rn | head -10

# Mail

# Deleting mail from MAIL-DAEMON in queue
for i in `mailq | grep MAILER-DAEMON | cut -f 1 -d " "`; do postsuper -d $i ; done

# So you get the number of all active mails with the command:
postqueue -p | egrep -c "^[0-9A-F]{10}[*]"

# and the number of all deferred mail with:
postqueue -p | egrep -c "^[0-9A-F]{10}[^*]"

# muestra cola
mailq

# elimina un correo de la cola pasando como parametro el ID
postsuper -d queue_id

# elimina todos los correos de la cola
postsuper -d ALL

# (Encolar de nuevo el mensaje)
postsuper -r Number 

# (Encolar de nuevo todos los mensajes)
postsuper -r ALL 

# (Mostrar la cola de correo por pantalla)
postqueue -p 

#  (Hacer un flush de la cola de correo, intentar enviar todos los correos)
postqueue -f

# postqueue -p is the same as mailq
postqueue -p = mailq    

# reload config
service postfix reload

# restart postfix server
service postfix restart 

# View the postfix version
postconf  mail_version

# Show default postfix values
postconf -d

# Show non default postfix values
postconf -n

# list mail queue and MAIL_ID's, list mail queue
mailq

# list mail queue and MAIL_ID's, list mail queue
postqueue -p

# flush mail queue
postfix  flush

# process the queue now
postqueue -f

# read email from mail queue
postcat -q MAIL_ID

# Visualizar el mensaje utilizando el ID
postcat -q ID 

# To remove MAIL_ID mail from the queue
postsuper -d MAIL_ID

# To remove all mails in the deferred queue
postsuper -d ALL deferred

# sort and count emails by "from address"
postqueue -p | awk '/^[0-9,A-F]/ {print $7}' | sort | uniq -c | sort -n           

# removing all emails sent by: user@adminlogs.info
postqueue -p | grep '^[A-Z0-9]'|grep user@adminlogs.info|cut -f1 -d' ' |tr -d \*|postsuper -d -

# remove all email sent from user@adminlogs.info
postqueue -p | awk '/^[0-9,A-F].*user@adminlogs.info / {print $1}' | cut -d '!' -f 1 | postsuper -d -      

# To delete all messages from the queue by a certain user:
for i in `postqueue -p | grep user@domain.com | awk '{print $1}' | grep -v host | grep -v \*`; do postsuper -d $i; done

# Elimina todos los correos enviados por el dominio @adminlogs.info
postqueue -p | grep '^[A-Z0-9]'|grep @adminlogs.info|cut -f1 -d' ' |tr -d \*|postsuper -d -

# Mail queue stats short
postqueue -p | tail -n 1

# number of emails in Mail queue
postqueue -p | grep -c "^[A-Z0-9]"    

# intenta enviar todos los mensajes que se encuentran en cola de espera
postqueue -f

# check log in realtime
tail -f /var/log/maillog    //watch logs live

# Funcion de enviar todos los mensajes
postfix flush

# Estado actual del servicio postfix
postfix status|start|stop|reload|abort

# Elimina todos los correos enviados por el dominio especificado en la cola de mensajes
mailq| grep ‘^[A-Z0-9]’|grep @dominio.com|cut -f1 -d’ ‘ |tr -d \*|postsuper -d

# Permite ver todos los correos en una estructura de arbol
qshape