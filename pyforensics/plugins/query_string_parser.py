









friendlyName = "Query String Parser"
description = "Extracts the query string from a URL and prints each field and value."
artifactTypes = ("url", "cache")  
remoteLookups = 0  
browser = "all"  
version = "20170225"  
parsedItems = 0  


def plugin(analysis_session=None):
    import urllib.parse

    
    global parsedItems
    parsedItems = 0

    for item in analysis_session.parsed_artifacts:              
        if item.row_type.startswith(artifactTypes):             
            if item.interpretation is None:                     
                parsed_url = urllib.parse.urlparse(item.url)
                query_string_dict = urllib.parse.parse_qs(parsed_url.query)

                if len(query_string_dict) > 0:                  
                    query_string = ''                           
                    for field, value in list(query_string_dict.items()):  
                        query_string += '{}: {} | '.format(field, value[0])

                    item.interpretation = query_string[:-2] + " [Query String Parser]"
                    parsedItems += 1                            

    
    return "{} query strings parsed".format(parsedItems)
