Microframework for testing Kong plugins.

This git repository has some submodules, use recursive clone.

It uses the latest 1.0.3 Kong!!! 
New Service/Route objects are used and PDK framework.

Dependencies
============

The only dependency to run this test suite is docker-ce.

If you have older Docker installer - remove it (Debian based distro considered):

`sudo apt-get remove docker docker-engine docker.io`

The simplest way to install docker-ce is as below (old distros may be not supported):

`curl http://get.docker.com/ | sudo sh`

General layout
==============

`specs` subfolder should contains fully automated tests only.

'lib' subfolder contains a files which may be reused by different tests.


How to test
===========

```
./t/run.sh jwt-auth
``` 

The test case start all required services, register a Service, then Route, configure demo plugin.

