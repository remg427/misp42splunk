# mispfetch
## Description

Use the `mispfetch` command to pull events or attributes from a [MISP](https://www.misp-project.org/) instance and **append** to the current set.  

`mispfect` is a very versatile command (like a Swiss knife) to pull information from MISP.
- All keys supported by MISP endpoint `/events/restSearch` or `/attributes/restSearch` can be used to build the HTTP body.
- In other words, any request that works with MISP REST client will work with `mispfetch`.
- there are arguments to further filter or format the results.

The simplest way is to create fields with the same names as the expected keys in the HTTP body and use `tojson` command to create an output field **misp\_http\_body**.

### mispfetch vs mispgetioc or mispgetevent
-   `mispfetch`
    * is a **streaming** command that **cannot** be on the first line of a search (or a sub-search).
    * all `mispfetch` arguments can be prepared on the SPL as fields before calling the custom command (see examples).
    * or passed on the same ligne as `mispfetch` (fields in the SPL have priority over the arguments on the command line).
    * therefore arguments values may be calculated based on the fields of the main search.
-   `mispgetioc`and `mispgetevent` 
    * are **generating** commands.
    * they must be on the first line of an SPL.
    * arguments must be on the same ligne. They may be prepared with a subsearch but this is complex and without link with main search.

## Syntax
#### | mispfetch
> **misp_instance**=string  
> **misp_restsearch**=(attributes|events)  
> **misp_http_body**=JSON object  
> attribute_limit=int  
> expand_object=bool  
> getioc=bool  
> keep_galaxy=bool  
> limit=int  
> misp\_output\_mode=(JSON|native)  
> not_tags=string (, comma-separated)  
> only_to_ids=bool  
> page=int  
> pipesplit=bool  
> tags=string (, comma-separated)  

#### Required arguments
With `mispfetch`, all arguments are defined as optional **but misp_instance must be a valid account name**. All other arguments have default values or are really optional.   

They can be set as field names (e.g. using `eval`) before calling `mispfetch`. If not defined as field names, they can be passed as arguments on the command line.  
Values set in field names have priority over the command arguments

The field has priority over the argument following `| mispfetc`

##### misp_instance
- **Syntax:** misp_instance=<string>  
- **Description:** this is the name of a MISP instance created under configuration tab.

##### misp_restsearch
- **Syntax:** misp_restsearch=<string>
- **Description:** define the restSearch endpoint. Either `events` or `attributes`.
- **Default:** `events`

##### misp\_http\_body
- **Syntax:** misp_http_body=<JSON>
- **Description:** A valid JSON request (use `tojson` to build it easily)

#### Optional arguments to query MISP

##### limit
- **Syntax:** limit=<int>
- **Description:** define the limit for each MISP search. 0 = no pagination.''',
- **Default:** 1000

##### not_tags
- **Syntax:** not_tags=CSV string*
- **Description:** Comma(,)-separated string of tags to exclude. Wildcard is %.

##### page
- **Syntax:** page=<int>
- **Description:** Define the page for each MISP search.
- **Default:** 1

##### tags
- **Syntax:** tags=CSV string
- **Description:** Comma(,)-separated string of tags to search for. Wildcard is `%`.

#### Optional arguments to filter result

##### attribute_limit
- **Syntax:** attribute_limit=<int>
- **Description:** Define the attribute_limit for the number of returned IOC for each MISP default.
- **Default:** `1000`

##### getioc
- **Syntax:** getioc=<bool>
- **Description:** Boolean to return the list of attributes together with the event.
- **Default:** `false`

##### keep_galaxy
- **Syntax:** keep_galaxy=<bool>
- **Description:** Boolean to remove galaxy part
- **Default:** `true`

##### only_to_ids
- **Syntax:** only_to_ids=<bool>
- **Description:** Boolean to search only attributes with the flag "to_ids" set to true.
- **Default:** `false`

#### Optional arguments to format result

##### misp\_output\_mode
- **Syntax:** misp_output_mode=<string>
- **Description:** define how to render on Splunk either as native tabular view or JSON object. Either `native` or `JSON`.
- **Default:** native'

##### expand_object
- **Syntax:** expand_object=<bool>
- **Description:** Boolean to have object attributes expanded one per line. By default, attributes of one object are displayed on same line.
- **Default:** `false`

##### pipesplit
- **Syntax:** pipesplit=<bool>
- **Description:** Boolean to split multivalue attributes.
- **Default:** `false`

## Usage

The `mispfetch` command is a dataset streaming command that appends data pulled from MISP instance to the current dataset.

### Basic examples

The minimum code to run the `mispfetch` is to set the argument `misp_instance`.

    | makeresults
    | eval misp_instance="misp_instance_name"
    | mispfetch

This will run the command will all default values.

A second example shows how argument misp\_http\_body can be build to make a query MISP.

Any argument supported by MISP REST API can be used. See MISP REST API documentation.  
This example introduces how arguments defined above can be set from the SPL or as argument of `mispfetch` command.  
The field in SPL has priority over the argument passed to the `mispfetch` command

    | makeresults
    | eval misp_instance="misp_instance_name", published_time="1d", published="True"
    | tojson misp_instance, published_time, published output_field=misp_http_body
    | mispfetch getioc=1 limit=100 attribute_limit=1000

The query is done on the endpoint `/events/restSearch`. It will return a maximum of 100 events published in the last day.  
Event attributes are also returned with a limit per event of 1000 attributes.

The third example uses the endpoint `/attributes/restSearch`.

    | makeresults
    | eval misp_instance="misp_instance_name", published_time="1d", published="True"
    | eval misp_restsearch="attributes", limit=0
    | tojson misp_instance, published_time, published output_field=misp_http_body
    | mispfetch getioc=1 limit=100 attribute_limit=1000

The query will returns all (limit=0 in SPL) attributes of events published in last day.
