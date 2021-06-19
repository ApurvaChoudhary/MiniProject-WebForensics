



















friendlyName = "Load Balancer Cookie Decoder"
description = "Decodes persistence cookies set by load balancers"
artifactTypes = ('cookie',)  
remoteLookups = 0  
browser = []  
browserVersion = []  
version = "20200213"  
parsedItems = 0  


def plugin(analysis_session=None):
    import re
    import struct
    if analysis_session is None:
        return

    def nsc_decode_service_name(service_name):
        """Decrypts the Caesar Substitution Cipher Encryption used on the NetScaler Cookie Name"""
        
        service_name_s = str(service_name)
        trans = str.maketrans('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
                              'zabcdefghijklmnopqrstuvwxyZABCDEFGHIJKLMNOPQRSTUVWXY')
        real_name = service_name_s.translate(trans)
        return real_name

    def nsc_decode_server_ip(server_ip):
        """Decrypts the XOR encryption used for the NetScaler Server IP"""
        ip_key = 0x03081e11
        decoded_ip = hex(server_ip ^ ip_key)
        t = decoded_ip[2:10].zfill(8)
        real_ip = '.'.join(str(int(i, 16)) for i in ([t[i:i + 2] for i in range(0, len(t), 2)]))
        return real_ip

    def nsc_decode_server_port(server_port):
        """Decrypts the XOR encryption used on the NetScaler Server Port"""
        port_key = 0x3630
        decoded_port = server_port ^ port_key  
        real_port = str(decoded_port)
        return real_port

    def big_ip_decode_cookie(encoded_string):
        (host, port, end) = encoded_string.split('.')

        
        (a, b, c, d) = [ord(i) for i in struct.pack("<I", int(host))]
        (v) = [ord(j) for j in struct.pack("<H", int(port))]
        p = "0x%02X%02X" % (v[0], v[1])
        return "{}.{}.{}.{}".format(a, b, c, d), int(p, 16)

    
    nsc_cookie_name_re = re.compile(r'^NSC_([a-zA-Z0-9\-_\.\*\+]*)')
    nsc_cookie_value_re = re.compile(r'[0-9a-f]{8}([0-9a-f]{8}).{24}([0-9a-f]{4})$')

    
    big_ip_cookie_value_re = re.compile(r'^\d{8,10}\.\d{1,5}\.\d{4}$')

    
    global parsedItems
    parsedItems = 0

    
    for item in analysis_session.parsed_artifacts:
        
        if item.row_type.startswith(artifactTypes):
            
            if item.interpretation is None:
                
                nsc_cookie_name_m = re.search(nsc_cookie_name_re, item.name)

                
                bigip_cookie_value_m = re.match(big_ip_cookie_value_re, item.value)

                
                if nsc_cookie_name_m:
                    
                    item.interpretation = "Service Name: {} "\
                        .format(nsc_decode_service_name(nsc_cookie_name_m.group(1)))

                    
                    cookie_value_m = re.search(nsc_cookie_value_re, item.value)
                    if cookie_value_m:
                        
                        item.interpretation += "| Server IP: {} | Server Port: {} "\
                            .format(nsc_decode_server_ip(int(cookie_value_m.group(1), 16)),
                                    nsc_decode_server_port(int(cookie_value_m.group(2), 16)))

                    
                    item.interpretation += "[NetScaler Cookie]"

                    
                    parsedItems += 1

                
                elif bigip_cookie_value_m:
                    try:
                        
                        item.interpretation = "Server IP: {} | Server Port: {} [BIG-IP Cookie]"\
                            .format(*big_ip_decode_cookie(bigip_cookie_value_m.group(0)))
                    except:
                        pass

                    
                    parsedItems += 1

    
    return "%s cookies parsed" % parsedItems
