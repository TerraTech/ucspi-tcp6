/*! \mainpage

ucspi-tcp6-1.11
===============

ucspi-tcp6 is an adoption of Dan Bernstein's ucspi-tcp
coming with IPv6 capabilities and requiring fehQlibs to build.

Requirements:
------------

- Install fehQlibs (usually located at /usr/local).

Installation:
-------------

- ucspi-tcp6 is expected to be installed under /package.
- ucspi-tcp6 follows the 'slashpackage' convention
  [http://cr.yp.to/unix.html].
- Untar the package here and move to /package/net/ucspi-tcp6-x.y.z.
- Execute in this directory 


     ./package/install

Customization:
--------------

- The path to qlibs is pre-defined in
  + conf-qlibs.
- You may adjust compiler and loader settings via
  + conf-cc and 
  + conf-ld.
- The path to install the binaries and man directory can be given via
  + conf-home and 
  + conf-man
  prior of installation.

If anything goes wrong, simply remove the ./compile directory and run

     ./package/compile 
     ./package/upgrade 
     ./package/run

again.

Further installation details can be found in ./doc/INSTALL.


Erwin Hoffmann, October, 2019. 
