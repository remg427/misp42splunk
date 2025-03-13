# mispfetch
## Description

Use the `mispfetch` command to pull events or attributes from a [MISP](https://www.misp-project.org/) instance and **append** to the current set.  

`mispfetch` is a very versatile command (like a Swiss knife) to pull information from MISP.
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

They can be set as field names (e.g. using `eval`) before calling `mispfetch`. If not defined as field names, they can be passed as arguments on the command line. A field value has priority over an argument following `| mispfetch`

- **misp_instance**
  - **Syntax:** `misp_instance=<string>`
  - **Description:** Specifies the MISP instance to use. The configuration must be defined in `local/misp42splunk_instances.conf`.

- **misp_restsearch**
    - **Syntax:** misp_restsearch=<string>
    - **Description:** define the restSearch endpoint. Either `events` or `attributes`. Default is `events`.

- **misp\_http\_body**
    - **Syntax:** misp\_http\_body=<JSON>
    - **Description:** A valid JSON request (use `tojson` to build it easily)

- **misp\_output\_mode**
    - **Syntax:** mmisp\_output\_mode=(fields|json)
    - **Description:** define how to render on Splunk either as native tabular view (`fields`)or JSON object (`json`). Default: is `fields`.

#### Optional arguments to query MISP
- **attribute_limit**
    - **Syntax:** `attribute_limit=<int>
    - **Description:**define the attribute_limit for max count of returned attributes for each MISP default. ; 0 = no limit. Default is 0.

- **expand_object**
  - **Syntax:** `expand_object=<bool>`
  - **Description:** Expands object attributes to one attribute per line. Default is `false`.

- **getioc**
  - **Syntax:** `getioc=<bool>`
  - **Description:** Retrieves the list of attributes along with the event. Default is `false`.

- **keep_galaxy**
  - **Syntax:** `keep_galaxy=<bool>`
  - **Description:** Retains galaxy information in the output. Default is `false`.

- **keep_related**
  - **Syntax:** `keep_related=<bool>`
  - **Description:** Includes related events per attribute in the output. Default is `false`.

- **limit**
  - **Syntax:** `limit=<int>`
  - **Description:** Limits the number of events retrieved. Default is `1000`.

- **not_tags**
  - **Syntax:** `not_tags=<CSV string>`
  - **Description:** Comma-separated list of tags to exclude from the search. Wildcard is `%`.

- **page**
  - **Syntax:** `page=<int>`
  - **Description:** Specifies the page number for paginated results. Default is `0` (fetches all pages).

- **pipesplit**
  - **Syntax:** `pipesplit=<bool>`
  - **Description:** Splits multivalue attributes into separate rows. Default is `true`.

- **prefix**
  - **Syntax:** `prefix=<string>`
  - **Description:** A string prefix for MISP keys.

- **tags**
  - **Syntax:** `tags=<CSV string>`
  - **Description:** Comma-separated list of tags to include in the search. Wildcard is `%`.

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
    | eval misp_restsearch="attributes", limit=1000
    | tojson misp_instance, published_time, published output_field=misp_http_body
    | mispfetch getioc=1 limit=100 attribute_limit=1000

The query will returns all attributes of events published in last day. Attributes will be retrieved by chunks of 1000 (`limit=1000`) iterating through all pages (default `page=0`)

