













friendlyName = "Google Analytics Cookie Parser"
description = "Parses Google Analytics cookies"
artifactTypes = 'cookie'
remoteLookups = 0
browser = "all"
browserVersion = 1
version = "20170130"
parsedItems = 0


def plugin(analysis_session=None):
    from pyforensics.utils import friendly_date
    import re
    import urllib.request, urllib.parse, urllib.error

    utma_re = re.compile(r'(\d+)\.(\d+)\.(\d{10})\.(\d{10})\.(\d{10})\.(\d+)')
    utmb_re = re.compile(r'(\d+)\.(\d+)\.\d+\.(\d{10})')
    utmc_re = re.compile(r'(\d+)')
    utmv_re = re.compile(r'(\d+)\.\|?(.*)')
    utmz_re = re.compile(r'(\d+)\.(\d{10})\.(\d+)\.(\d+)')
    utmz_parameters_re = re.compile(r'(\d+)\.(\d{10})\.(\d+)\.(\d+)\.(.*)')
    utmz_extract_parameters_re = re.compile(r'(.+?)=(.+)')
    ga_re = re.compile(r'GA1\.\d+\.(\d+)\.(\d{10})$')

    global parsedItems
    parsedItems = 0

    for item in analysis_session.parsed_artifacts:
        if item.row_type.startswith(artifactTypes):
            if item.name == '__utma':
                
                m = re.search(utma_re, item.value)
                if m:
                    item.interpretation = 'Domain Hash: {} | Unique Visitor ID: {} | First Visit: {} | ' \
                                          'Previous Visit: {} | Last Visit: {} | Number of Sessions: {} | ' \
                                          '[Google Analytics Cookie]'\
                        .format(m.group(1), m.group(2), friendly_date(m.group(3)),
                                friendly_date(m.group(4)), friendly_date(m.group(5)),
                                m.group(6))
                    parsedItems += 1
            if item.name == '__utmb':
                m = re.search(utmb_re, item.value)
                if m:
                    item.interpretation = 'Domain Hash: {} | Pages Viewed: {} | Last Visit: {} | ' \
                                          '[Google Analytics Cookie]' \
                                          .format(m.group(1), m.group(2), friendly_date(m.group(3)))
                    parsedItems += 1
            if item.name == '__utmc':
                m = re.search(utmc_re, item.value)
                if m:
                    item.interpretation = 'Domain Hash: {} | [Google Analytics Cookie]'.format(m.group(1))
                    parsedItems += 1
            if item.name == '__utmv':
                m = re.search(utmv_re, item.value)
                if m:
                    item.interpretation = 'Domain Hash: {} | Custom Values: {} | [Google Analytics Cookie]' \
                                          .format(m.group(1), urllib.parse.unquote_plus(m.group(2)))
                    parsedItems += 1
            if item.name == '__utmz':
                m = re.search(utmz_re, item.value)
                if m:
                    derived = 'Domain Hash: {} | Last Visit: {} | Sessions: {} | Sources: {} | ' \
                              .format(m.group(1), friendly_date(m.group(2)), m.group(3), m.group(4))
                    parsedItems += 1
                    p = re.search(utmz_parameters_re, item.value)

                    parameters = {}
                    raw_parameters = p.group(5)[3:]  

                    
                    for pair in raw_parameters.split('|utm'):               
                        
                        rp = re.search(utmz_extract_parameters_re, pair)    
                        try:
                            parameters[rp.group(1)] = rp.group(2)           
                        except AttributeError:
                            pass
                    if 'cmd' in parameters:
                        
                        if parameters['cmd'] == 'referral':
                            if 'csr' in parameters and 'cct' in parameters:
                                derived += 'Referrer: {}{} | '.format(parameters['csr'], parameters['cct'])
                            if parameters['ccn'] != '(referral)':
                                derived += 'Ad Campaign Info: {} | '.format(urllib.parse.unquote_plus(parameters['ccn']))

                        
                        elif parameters['cmd'] == 'organic':
                            derived += 'Last Type of Access: {} | '.format(parameters['cmd'])
                            if 'ctr' in parameters:
                                derived += 'Search keywords: {} | '.format(urllib.parse.unquote_plus(parameters['ctr']))
                            if parameters['ccn'] != '(organic)':
                                derived += 'Ad Campaign Info: %s | '.format(parameters['ccn'])

                        
                        elif parameters['cmd'] != 'none' and parameters['ccn'] == '(direct)':
                            derived += 'Last Type of Access: {} | '.format(urllib.parse.unquote_plus(parameters['ccn']))
                            if 'ctr' in parameters:
                                derived += 'Search keywords: {} | '.format(urllib.parse.unquote_plus(parameters['ctr']))

                    
                    else:
                        if 'csr' in parameters:
                            derived += 'Last Source Site: {} | '.format(parameters['csr'])
                        if 'ccn' in parameters:
                            derived += 'Ad Campaign Info: {} | '.format(urllib.parse.unquote_plus(parameters['ccn']))
                        if 'cmd' in parameters:
                            derived += 'Last Type of Access: {} | '.format(parameters['cmd'])
                        if 'ctr' in parameters:
                            derived += 'Keyword(s) from Search that Found Site: {} | '.format(parameters['ctr'])
                        if 'cct' in parameters:
                            derived += 'Path to the page on the site of the referring link: {} | '.format(parameters['cct'])

                    derived += '[Google Analytics Cookie] '
                    item.interpretation = derived
            if item.name == '_ga':
                m = re.search(ga_re, item.value)
                if m:
                    item.interpretation = 'Client ID: {}.{} | First Visit: {} | [Google Analytics Cookie]' \
                        .format(m.group(1), m.group(2), friendly_date(m.group(2)))
                    parsedItems += 1

    
    return '{} cookies parsed'.format(parsedItems)
