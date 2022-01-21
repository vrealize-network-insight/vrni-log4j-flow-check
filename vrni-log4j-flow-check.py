
import requests
import time
import csv
import swagger_client
from swagger_client.rest import ApiException
from init_api_client import parse_arguments, get_api_client
import urllib3
urllib3.disable_warnings()

debug = False
CSV_URL = "https://gist.githubusercontent.com/blotus/f87ed46718bfdc634c9081110d243166/raw/7a8ecd395a5818a2a4aec7a185fa2204366173ae/log4j_exploitation_attempts_crowdsec.csv"


class bcolors:
    OK = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'


def main(args):
    # Create search API client object
    search_api = swagger_client.SearchApi()

    # get IP list
    print("Getting known bad actors from: {}".format(CSV_URL))
    response = requests.get(CSV_URL)

    text = response.iter_lines(decode_unicode='utf-8')
    reader = csv.reader(text, delimiter=',')

    # go through each IP address, check if the result is validated (not pending, beneign, or not enough data)
    # and run a search in vRNI against it
    for row in reader:
        if row[1] == "validated":
            validated_ip = row[0]

            search_string = "flows where source IP = '{}'".format(validated_ip)
            # Create request parameters required for search APIs
            public_api_search_request_params = dict(query=search_string,
                                                    size=1000)
            if debug:
                print("Running search = [{}]".format(search_string))

            # Create payload from search parameters required for calling the search API
            search_payload = swagger_client.SearchQueryRequest(
                **public_api_search_request_params)

            # Call the search API
            api_response = search_api.search(body=search_payload)

            if api_response.entity_list_response['total_count'] > 0:
                print(bcolors.WARNING + "Flows found for IP '" + validated_ip + "'")
            else:
                print(bcolors.OK + "No flows found for IP '" + validated_ip + "'")

            if debug:
                print("Response attributes: Total Count: {} "
                      "Time: {}".format(api_response.entity_list_response['total_count'],
                                        time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(api_response.entity_list_response['end_time']))))
            for result in api_response.entity_list_response['results']:
                entities_api = swagger_client.EntitiesApi()

                internet_flow = entities_api.get_flow(id=result['entity_id'])
                print("Flow: {}".format(internet_flow.name))
                # make sure we don't hit the vRNI throttle and start getting 429 errors
                time.sleep(0.025)

            if api_response.entity_list_response['total_count'] > 0:
                if args.platform_ip:
                    print(bcolors.WARNING + "More info: https://{}/#search/query/%22flows%20where%20source%20IP%20%3D%20{}%22/timemeta/".format(
                        args.platform_ip, validated_ip) + "{"+"%22timePreset%22%3A%22Now%22"+"}"+"/sourceString/%22USER%22")
                else:
                    print(bcolors.WARNING + "More info: https://www.mgmt.cloud.vmware.com/ni/#search/query/%22flows%20where%20source%20IP%20%3D%20{}%22/timemeta/".format(
                        validated_ip) + "{"+"%22timePreset%22%3A%22Now%22"+"}"+"/sourceString/%22USER%22")

            # make sure we don't hit the vRNI throttle and start getting 429 errors
            time.sleep(0.025)


if __name__ == '__main__':
    args = parse_arguments()
    args_parsed = args.parse_args()
    api_client = get_api_client(args_parsed)
    main(args_parsed)
