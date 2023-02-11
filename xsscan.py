import requests
from pprint import pprint
from bs4 import BeautifulSoup
import pyfiglet
from urllib.parse import urljoin
import argparse
from time import sleep

parse = argparse.ArgumentParser()

parse.add_argument('-u', '--url', required=True,
                   help='URL TARGET: https:exemple.com.br/FUZZ')
parse.add_argument('-w', '--wordlist', required=False)
parse.add_argument('-c', '--cookie', help='COKKIESS!')

args = parse.parse_args()


url = args.url
wordlist = args.wordlist
cookie = args.cookie

header = {
    'cookie': cookie
}


def app_banner(url,  payload):
    banner = pyfiglet.Figlet(font='slant')

    print(banner.renderText('XSScanner'))
    print('v0.1')
    print('-' * 50)
    sleep(1)
    print(':: Payload:      :', str(payload))
    print(':: URL:          :', str(url))
    print('-' * 50, '\n')
    print('[+] Warning: This is Cross-site Script vulnerability testing software, do not use it without prior permission because this is an illegal action.')
    print('Use only in authorized environments and that have full control, I am not responsible for misuse of the application.\n')
    sleep(2)


def get_all_forms(url):
    soup = BeautifulSoup(requests.get(
        url, headers=header).content, 'html.parser')
    return soup.find_all('form')


def get_form_details(form):
    details = {}

    action = form.attrs.get('action', '').lower()
    method = form.attrs.get('method', 'get').lower()

    inputs = []
    for input_tag in form.find_all('input'):
        input_type = input_tag.attrs.get('type', 'text')
        input_name = input_tag.attrs.get('name')
        inputs.append({'type': input_type, 'name': input_name})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs

    return details


def submit_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]

    data = {}

    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value

        input_name = input.get("name")
        input_value = input.get("value")

        if input_name and input_value:
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:

        return requests.get(target_url, params=data)


def scan_xss_with_wordlist(url):
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    with open(wordlist, encoding='utf8') as file:
        line = file.readlines()
        count = 0
    for index in line:
        payload = index
        payload = index
        is_vulnerable = False

        for form in forms:
            form_details = get_form_details(form)
            content = submit_form(
                form_details, url, payload).content.decode()
            if payload in content:
                count += 1
                print(f"[+] {count} XSS Detected on {url}")
                print(f'PAYLOAD: {index}')
                is_vulnerable = True

        count += 1
        print(f'\r Progress: {len(line)} : {count} -- ', end='')
    return is_vulnerable


def scan_xss(url):
    payload = "<Script>confirm('hi')</scripT>"
    is_vulnerable = False

    app_banner(url, payload)
    if wordlist:
        scan_xss_with_wordlist(url)
        exit(1)

    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")

    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, payload).content.decode()
        if payload in content:
            print(f"[+] XSS Detected on {url}")
            print(f"[*] Form details:")
            is_vulnerable = True
        pprint(form_details)

        if is_vulnerable:
            print('-' * 50)
            print("[+] Target is vulnerable")
            print('-' * 50, '\n')
        else:
            print('-' * 50)
            print("[+] Target is not vulnerable")
        


scan_xss(url)
