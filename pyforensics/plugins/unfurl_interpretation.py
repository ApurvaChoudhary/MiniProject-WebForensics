








from unfurl import core
import unfurl
import logging


try:
    unfurl.log.setLevel(logging.CRITICAL)
except Exception:
    pass


friendlyName = "Unfurl"
description = "Run storage values through Unfurl"
artifactTypes = ["local storage"]  
remoteLookups = 1  
browser = "Chrome"  
browserVersion = 1  
version = "20210424"  
parsedItems = 0  


def plugin(target_browser):

    
    global parsedItems
    parsedItems = 0

    for item in target_browser.parsed_storage:
        
        if item.row_type not in artifactTypes:
            continue

        
        try:
            u = core.Unfurl()
            u.add_to_queue(data_type='url', key=None, value=item.value)
            u.parse_queue()
            u_json = u.generate_json()

        
        
        
        except:
            continue

        
        if u_json['summary'] == {}:
            continue

        
        
        if len(u_json['nodes']) == 2:
            item.interpretation = f"{u_json['nodes'][1]['label']}"

            
            desc = u_json['nodes'][1].get('title', None)
            if not desc:
                desc = u_json['edges'][0].get('title', None)
            if desc:
                item.interpretation += f' ({desc})'

            item.interpretation += f' [Unfurl]'

        
        elif len(u_json['nodes']) == 3 and u_json['nodes'][2]['label'].startswith('Version 4 UUID'):
            item.interpretation = 'Value is a Version 4 UUID (randomly generated)'

        elif len(u_json['nodes']) == 3 and u_json['nodes'][2]['label'].startswith('Version 5 UUID'):
            item.interpretation = 'Value is a Version 5 UUID (generated based on a namespace and a name, ' \
                                  'which are combined and hashed using SHA-1)'

        elif len(u_json['nodes']) == 6 and u_json['nodes'][2]['label'].startswith('Version 1 UUID'):
            item.interpretation = f"{u_json['nodes'][5]['label']} (Time Generated); " \
                                  f"{u_json['nodes'][4]['label']} (MAC address); " \
                                  f"Value is a Version 1 UUID (based on time and MAC address) [Unfurl]"

        
        else:
            item.interpretation = f"{u.generate_text_tree()} \n[Unfurl]"

        parsedItems += 1

    
    return f'{parsedItems} values parsed'
