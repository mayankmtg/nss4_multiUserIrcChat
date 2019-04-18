#!/bin/sh

make

chown fr nssserver
chgrp root nssserver
mv nssserver /usr/bin/
chmod u+s /usr/bin/nssserver

chown fr nssclient
chgrp root nssclient
mv nssclient /usr/bin/
chmod u+s /usr/bin/nssclient