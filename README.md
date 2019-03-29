# traceroute

## Preface

traceroute is based on the ICMP protocol, and can test the route you trece easily.

## <del>Usage</del>

```bash
traceroute [-P][protocol] [-t][ttl][host]
Usage:
-P  protocol. ICMP, UDP, TCP argument.
-t  time to live.
```

## API Documents
There are there apis total. we provide two methods to process the results, one is the asynchronization method, we recommend you using this way to handle the process because the traceroute work would take long time; the other is the synchronization method， ather the traceroute work is finished, the result will give.

- ```int traceroute_init(traceroute **tpp,  char **err_msg);``` initalizes a traceroute struct pointer including the config and operation handler, if it's failed that will return 0 and get the error meessge from the ```err_msg``` argument. 
- ```int traceroute_run_async(traceroute *tp, int (*success_callback)(char *route, long long *ms, INFO info), int (*err_callback)(char *err_msg));```handles the async working. First argument ```ip``` pointer had been initalized before. Success will execute the ```success_callback```, failure will execute the ```err_callback```. ```success_callback```including there params, more details plaese see the test.
-```int traceroute_free(traceroute *tp)```destorys the traceroute pointer and voids the memory leak.

## Furtures

+ [ ] IPv6 support
+ [+] DNS support
+ [ ] TCP support
+ [ ] synchronization method 
+ [ ] others
## License

MIT License
