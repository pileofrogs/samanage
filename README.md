# samanage
samanage api in python

user must be familiar with samanage API.  Objects/Hashes incorrectly formatted can be very difficult to debug.

Differences between this version and original:
 - can get more than 100 items
   - count means max items retrieved
   - pagesize means number of items returned per http exchange (count used to mean this)
 - dynamic class generator means
   - every type offered by samanage can (in theory) be handled
   - every attribute is represented 
   - There is no attribute checking

