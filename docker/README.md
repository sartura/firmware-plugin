docker for firmware Sysrepo plugin.

## build dockerfile

```
$ docker build -t sysrepo/sysrepo-netopeer2:firmware -f Dockerfile .
```

## run dockerfile with supervisor

```
$ docker run -i -t -v /opt/yang:/opt/fork --name firmware --rm sysrepo/sysrepo-netopeer2:firmware
```

## run dockerfile without supervisor

```
$ docker run -i -t -v /opt/yang:/opt/fork --name firmware --rm sysrepo/sysrepo-netopeer2:firmware bash
$ ubusd &
$ rpcd &
$ sysrepod
$ sysrepo-plugind
$ netopeer2-server
```
