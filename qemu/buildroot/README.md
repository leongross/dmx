# Buildroot Linux Distribution
To create a minimal file system packed with user land utilities we use buildroot.
The kernel is not included in the image.


## Configuration
Configure the buildroot filesystem and copy the config to the [config](../config) folder.
```sh
$ make menuconfig
```

Configure the busybox used in the buildroot filesystem
```sh
$ make busybox
```

Create devices for dm-mintegrity testing.
The devices are mounted into the virtual machine.
```sh
$ make test-dev
```


## Run
Run [kernel](../../linux) with buildroot file system.
```sh
$ make start
```

Run [kernel](../../linux) with buildroot file system in debug mode ofr gdb to attach.
Attachment has to be done separately (see [instructions](../README.md##Run)).
```sh
$ make start-debug
```
