
## custom command mispgetioc
This custom command must be the first of a search (or a sub-search). The results are displayed in a table.
The command syntax is as follow:

    |mispgetioc ( [eventid=id] | [last=interval] )
                [onlyids=y|n]
                [category=string]
                [type=string]
                **[getuuid=y|n|Y|N|0|1]**
                **[getorg=y|n|Y|N|0|1]**
                [server=https://host:port] 
                [authkey=misp-authorization-key]
                [sslcheck=y|n]                  
                

- You must set either parameter 'eventid' or 'last'
    + eventid is the numeric value on the instance. (if you think uuid should be an option intoduce an issue or pull request)
    + last interval is a number followed by a letter d(ays), h(ours) or m(inutes)

- The other parameters are optional
    + you may filter the results using onlyids (boolean), [type](https://www.circl.lu/doc/misp/categories-and-types/#types) and [category](https://www.circl.lu/doc/misp/categories-and-types/#categories) parameters
    + you may set getuuid=Y to get the event uuid in the results 
    + likewise set getorg=Y to list the originating organisation

- If you need to fecth from another MISP instance different from the default one defined in the setup of the app, you may overwrite the misp server parameters for this search by setting
    + server: set the url to the MISP instance
    + authkey: misp-authorization-key for this instance
    + sslcheck: you may check ssl certificate (default no)  