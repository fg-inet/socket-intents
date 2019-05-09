Changes
=======

This document describes significant changes to the Socket Intents prototype in different releases, with the latest changes at the top.

release-0.8
-----------

* Add simplified MPTCP policy which enables MPTCP for every socket
* Finalize Threshold Policy with advanced capacity estimation and load time computation with slow start
* Fix some memory management issues

release-0.7
-----------

* Refactor and extend path characteristics collection in Multi Access Manager (Linux-only!)
* Update and add Policies: "Earliest Arrival First", "Threshold", "Biased Choice" ("Probabilities")
* Fix memory management issues in MAM

Note: This update adds a lot of Linux-only functionality. It currently does not compile on Mac OS.


release-0.6
-----------

* Add asynchronous socketconnect API
* Refactor code structure of APIs
* Refactor path characteristics collection
