# mispfetch
## Description

Use the `mispfetch` command to pull events or attributes from a [MISP](https://www.misp-project.org/) instance and **append** to the current set.  

`mispfect` is very versatile command (like a Swiss knife) to pull information from MISP.
- All parameters supported by MISP endpoint `/events/restSearch` or `/attributes/restSearch` can be used to build the HTTP body.

- In other words, any request that works with MISP REST client will work with `mispfetch`.

- there are parameters to further filter or format the results.

The simple way is to set the parameters and use `tojson`command to create an output field misp\_http\_body.

```python

```

### mispfetch vs mispgetioc/mispgetevent
-   `mispfetch`is a **streaming** command that **cannot** be on the first of a search (or a sub-search).
-   all parameters of `mispfetch` can be prepared on the SPL before calling the custom command (see examples).
-   `mispgetioc`and `mispgetevent` are **generating** commands; they must be on the first line of an SPL.

## Syntax
#### | mispfetch

#### Required arguments
With `mispfetch` there is no mandatory arguments set to keep the choice of setting them using the parameter key or an eval to have a field with the same name as the parameter.  

The field has priority over the argument following `| mispfetc`

But for the command to work, 3 arguments are required

##### misp_instance
- **Syntax:** misp_instance=<string>  
- **Description:** this is the name of a MISP instance created under configuration tab.

##### misp_restsearch
- **Syntax:** misp_restsearch=<string>
- **Description:** define the restSearch endpoint. Either `events` or `attributes`.
- **Default:** `events`

##### misp\_http\_body
- **Syntax:** misp_http_body=<JSON>
- **Description:**Valid JSON request

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

The following example shows how to use pagination and return results from several pages

    | makeresults
    | eval misp_instance="misp_instance_name", published_time="1d", published="True"
    | eval misp_restsearch="attributes", limit=100
    | tojson misp_instance, published_time, published output_field=misp_http_body
    | mispfetch getioc=1 limit=100 attribute_limit=1000 page=1
    | eval page=2
    | mispfetch getioc=1 limit=100 attribute_limit=1000 page=1

