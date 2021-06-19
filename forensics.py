import argparse
import datetime
import importlib
import logging
import os
import re
import shutil
import sys
import time

import pyforensics
import pyforensics.plugins
from pyforensics.analysis import AnalysisSession
from pyforensics.utils import banner, format_meta_output, format_plugin_output


try:
    import pytz
except ImportError:
    print(f'Could not import module \'pytz\'; all timestamps in XLSX output '
          f'will be in examiner local time ({time.tzname[time.daylight]}).')


def parse_arguments(analysis_session):
    description = f'''Internet history forensics for Google Chrome/Chromium.

This script parses the files in the Chrome/Chromium/Brave data folder, runs various plugins
   against the data, and then outputs the results in a spreadsheet. '''

    epi = r'''
Example:  C:\forensics.py -i "C:\Users\Apurva\AppData\Local\Google\Chrome\User Data\Default" -o test_case
    '''

    class MyParser(argparse.ArgumentParser):
        def error(self, message):
            sys.stderr.write('error: %s\n' % message)
            self.print_help()
            sys.exit(2)

    parser = MyParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=description,
        epilog=epi)

    parser.add_argument('-i', '--input', required=True,
                        help='Path to the Chrome(ium) profile directory (typically "Default"). If a higher-level '
                             'directory is specified instead, Hindsight will recursively search for profiles.', )
    parser.add_argument('-o', '--output', help='Name of the output file (without extension)')
    parser.add_argument('-b', '--browser_type', help='Type of input files', default='Chrome',
                        choices=['Chrome', 'Brave'])
    parser.add_argument('-f', '--format', choices=analysis_session.available_output_formats,
                        default=analysis_session.available_output_formats[-1], help='Output format')
    parser.add_argument('-l', '--log', help='Location Hindsight should log to (will append if exists)',
                        default=os.path.join(os.getcwd(), 'hindsight.log'))
    parser.add_argument('-t', '--timezone', help='Display timezone for the timestamps in XLSX output', default='UTC')
    parser.add_argument('-d', '--decrypt', choices=['mac', 'linux'], default=None,
                        help='Try to decrypt Chrome data from a Linux or Mac system; support for both is currently '
                             'buggy and enabling this may cause problems. Only use "--decrypt linux" on data from a '
                             'Linux system, and only use "--decrypt mac" when running Hindsight on the same Mac the '
                             'Chrome data is from.')
    parser.add_argument('-c', '--cache',
                        help='Path to the cache directory; only needed if the directory is outside the given "input" '
                             'directory. Mac systems are set up this way by default. On a Mac, the default cache '
                             'directory location for Chrome is <userdir>/Library/Caches/Google/Chrome/Default/Cache/')
    parser.add_argument('--nocopy', '--no_copy', help='Don\'t copy files before opening them; this might run faster, '
                                                      'but some locked files may be inaccessible', action='store_true')
    parser.add_argument('--temp_dir', default='hindsight-temp',
                        help='If files are copied before being opened, use this directory as the copy destination')

    args = parser.parse_args()

    if args.timezone:
        try:
            __import__('pytz')
        except ImportError:
            args.timezone = None
        else:
            try:
                args.timezone = pytz.timezone(args.timezone)
            except pytz.exceptions.UnknownTimeZoneError:
                print("Couldn't understand timezone; using UTC.")
                args.timezone = pytz.timezone('UTC')

    
    if args.decrypt == 'linux' and analysis_session.available_decrypts['linux'] == 1:
        analysis_session.available_decrypts['linux'] = 1
    else:
        analysis_session.available_decrypts['linux'] = 0

    
    if args.decrypt == 'mac' and analysis_session.available_decrypts['mac'] == 1:
        analysis_session.available_decrypts['mac'] = 1
    else:
        analysis_session.available_decrypts['mac'] = 0

    return args


def main():

    def write_excel(analysis_session):
        import io

        
        string_buffer = io.BytesIO()

        
        analysis_session.generate_excel(string_buffer)

        
        string_buffer.seek(0)

        
        with open(f'{analysis_session.output_name}.{analysis_session.selected_output_format}', 'wb') as file_output:
            shutil.copyfileobj(string_buffer, file_output)

    def write_sqlite(analysis_session):
        output_file = analysis_session.output_name + '.sqlite'

        if os.path.exists(output_file):
            if os.path.getsize(output_file) > 0:
                print(('\nDatabase file "{}" already exists.\n'.format(output_file)))
                user_input = input('Would you like to (O)verwrite it, (R)ename output file, or (E)xit? ')
                over_re = re.compile(r'(^o$|overwrite)', re.IGNORECASE)
                rename_re = re.compile(r'(^r$|rename)', re.IGNORECASE)
                exit_re = re.compile(r'(^e$|exit)', re.IGNORECASE)
                if re.search(exit_re, user_input):
                    print("Exiting... ")
                    sys.exit()
                elif re.search(over_re, user_input):
                    os.remove(output_file)
                    print(("Deleted old \"%s\"" % output_file))
                elif re.search(rename_re, user_input):
                    output_file = "{}_1.sqlite".format(output_file[:-7])
                    print(("Renaming new output to {}".format(output_file)))
                else:
                    print("Did not understand response.  Exiting... ")
                    sys.exit()

        analysis_session.generate_sqlite(output_file)

    def write_jsonl(analysis_session):
        output_file = analysis_session.output_name + '.jsonl'
        analysis_session.generate_jsonl(output_file)

    print(banner)

    
    real_path = os.path.dirname(os.path.realpath(sys.argv[0]))

    
    analysis_session = AnalysisSession()

    
    args = parse_arguments(analysis_session)

    if args.output:
        analysis_session.output_name = args.output

    if args.cache:
        analysis_session.cache_path = args.cache

    analysis_session.selected_output_format = args.format
    analysis_session.browser_type = args.browser_type
    analysis_session.timezone = args.timezone
    analysis_session.no_copy = args.nocopy
    analysis_session.temp_dir = args.temp_dir
    analysis_session.log_path = args.log

    
    logging.basicConfig(filename=analysis_session.log_path, level=logging.DEBUG,
                        format='%(asctime)s.%(msecs).03d | %(levelname).01s | %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    log = logging.getLogger(__name__)

    
    log.info(
        '\n' + '#' * 80 +
        f'\n###    Hindsight v{pyforensics.__version__} (https://github.com/obsidianforensics/hindsight)    ###\n' +
        '#' * 80)

    
    print((format_meta_output("Start time", str(datetime.datetime.now())[:-3])))

    
    analysis_session.input_path = args.input
    print((format_meta_output('Input directory', args.input)))
    print((format_meta_output(
        'Output name', f'{analysis_session.output_name}.{analysis_session.selected_output_format}')))

    
    print("\n Processing:")
    run_status = analysis_session.run()
    if not run_status:
        return False

    print("\n Running plugins:")
    log.info("Plugins:")
    completed_plugins = []

    
    log.info(" Built-in Plugins:")
    for plugin in pyforensics.plugins.__all__:
        
        if plugin in completed_plugins:
            continue

        log.debug(f" - Loading '{plugin}'")
        try:
            module = importlib.import_module(f'pyforensics.plugins.{plugin}')
        except ImportError as e:
            log.error(f' - Error: {e}')
            print((format_plugin_output(plugin, "-unknown", 'import failed (see log)')))
            continue
        except Exception as e:
            log.error(f' - Exception in {plugin} plugin: {e}')

        try:
            log.info(f" - Running '{module.friendlyName}' plugin")
            parsed_items = module.plugin(analysis_session)
            print((format_plugin_output(module.friendlyName, module.version, parsed_items)))
            log.info(f' - Completed; {parsed_items}')
            completed_plugins.append(plugin)
        except Exception as e:
            print((format_plugin_output(module.friendlyName, module.version, 'failed')))
            log.info(f' - Failed; {e}')

    
    log.info(" Custom Plugins:")

    if real_path not in sys.path:
        sys.path.insert(0, real_path)

    
    for potential_path in sys.path:
        
        for potential_plugin_path in [os.path.join(potential_path, 'plugins'),
                                      os.path.join(potential_path, 'pyforensics', 'plugins')]:
            if os.path.isdir(potential_plugin_path):
                log.info(" Found custom plugin directory {}:".format(potential_plugin_path))
                try:
                    
                    sys.path.insert(0, potential_plugin_path)

                    
                    plugin_listing = os.listdir(potential_plugin_path)

                    log.debug(" - Contents of plugin folder: " + str(plugin_listing))
                    for plugin in plugin_listing:
                        if plugin[-3:] == ".py" and plugin[0] != '_':
                            plugin = plugin.replace(".py", "")

                            
                            if plugin in completed_plugins:
                                log.debug(" - Skipping '{}'; a plugin with that name has run already".format(plugin))
                                continue

                            log.debug(" - Loading '{}'".format(plugin))
                            try:
                                module = __import__(plugin)
                            except ImportError as e:
                                log.error(f' - Error: {e}')
                                print((format_plugin_output(plugin, "-unknown", 'import failed (see log)')))
                                continue
                            except Exception as e:
                                log.error(f' - Exception in {plugin} plugin: {e}')

                            try:
                                log.info(" - Running '{}' plugin".format(module.friendlyName))
                                parsed_items = module.plugin(analysis_session)
                                print((format_plugin_output(module.friendlyName, module.version, parsed_items)))
                                log.info(" - Completed; {}".format(parsed_items))
                                completed_plugins.append(plugin)
                            except Exception as e:
                                print((format_plugin_output(module.friendlyName, module.version, 'failed')))
                                log.info(" - Failed; {}".format(e))
                except Exception as e:
                    log.debug(' - Error loading plugins ({})'.format(e))
                    print('  - Error loading plugins')
                finally:
                    
                    sys.path.remove(potential_plugin_path)

    
    if os.path.dirname(analysis_session.output_name) != "" \
            and not os.path.exists(os.path.dirname(analysis_session.output_name)):
        os.makedirs(os.path.dirname(analysis_session.output_name))

    
    if analysis_session.selected_output_format == 'xlsx':
        log.info("Writing output; XLSX format selected")
        try:
            print(("\n Writing {}.xlsx".format(analysis_session.output_name)))
            write_excel(analysis_session)
        except IOError:
            type, value, traceback = sys.exc_info()
            print((value, "- is the file open?  If so, please close it and try again."))
            log.error("Error writing XLSX file; type: {}, value: {}, traceback: {}".format(type, value, traceback))

    elif args.format == 'jsonl':
        log.info("Writing output; JSONL format selected")
        print(("\n Writing {}.jsonl".format(analysis_session.output_name)))
        write_jsonl(analysis_session)

    elif args.format == 'sqlite':
        log.info("Writing output; SQLite format selected")
        print(("\n Writing {}.sqlite".format(analysis_session.output_name)))
        write_sqlite(analysis_session)

    
    print(f'\n Finish time: {str(datetime.datetime.now())[:-3]}')
    log.info(f'Finish time: {str(datetime.datetime.now())[:-3]}\n\n')


if __name__ == "__main__":
    main()
