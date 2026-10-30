#!/usr/bin/env python3
"""Trae 积分监控（只读）

从 accessToken 查询 Trae 积分余额，不签到、不修改任何状态。
支持多账号、企业微信推送。

Endpoint: GET https://api.trae.cn/trae/api/v2/pay/user_current_entitlement_list
"""
import argparse, json, os, platform, sys
import urllib.request
import urllib.error
import logging


_LOGGER = logging.getLogger(__name__)


UA = 'Trae/1.107.1'
EP_ENTITLE = 'https://api.trae.cn/trae/api/v2/pay/user_current_entitlement_list'
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def ug_headers(token, device_id=''):
    headers = {'Authorization': 'Cloud-IDE-JWT ' + token,
               'User-Agent': UA, 'Content-Type': 'application/json', 'Accept': 'application/json'}
    if device_id:
        headers['x-device-id'] = device_id
    headers['x-device-type'] = platform.system() or 'Windows'
    headers['x-os-version'] = platform.version() or '10.0.19045'
    headers['x-app-version'] = '1.107.1'
    return headers


def _post(url, headers, body='{}', timeout=30):
    req = urllib.request.Request(url, data=body.encode('utf-8'),
                                 headers=headers, method='POST')
    try:
        with _opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')
    except Exception as e:
        return -1, str(e)


def query_credits(access_token, device_id=''):
    status, text = _post(EP_ENTITLE, ug_headers(access_token, device_id),
                         '{"req_source":1}', timeout=15)
    if status != 200:
        return {'ok': False, 'status': status, 'text': text[:200]}
    try:
        data = json.loads(text)
        ents = data.get('Result', {}).get('EntitlementList', [])
        used = sum(e.get('UsedCount', 0) for e in ents)
        avail = sum(e.get('AvailableCount', 0) for e in ents)
        return {'ok': True, 'used': used, 'available': avail, 'detail': ents}
    except Exception as e:
        return {'ok': False, 'parse': str(e), 'text': text[:200]}


def load_accounts_from_env():
    raw = os.environ.get('TRAE_ACCOUNTS', '').strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if not isinstance(data, list):
            return []
        return data
    except Exception:
        return []


def main():
    parser = argparse.ArgumentParser(description='Trae 积分监控（只读）')
    parser.add_argument('files', nargs='*', help='JSON 文件路径')
    parser.add_argument('--env', action='store_true', help='从 TRAE_ACCOUNTS 读取')
    parser.add_argument('--json', action='store_true', help='JSON 输出')
    args = parser.parse_args()

    accounts = []
    for fp in args.files:
        try:
            with open(fp, 'r', encoding='utf-8') as f:
                data = json.load(f)
            items = data.get('accounts', data) if isinstance(data, dict) else data
            if isinstance(items, list):
                for a in items:
                    at = a.get('accessToken') or a.get('token') or ''
                    if at:
                        accounts.append({'name': a.get('name', '?'),
                                         'accessToken': at,
                                         'deviceId': a.get('deviceId', '')})
        except Exception as _exc:
            _LOGGER.debug("忽略预期内异常（降级路径）: %s", _exc)
    if args.env:
        for a in load_accounts_from_env():
            at = a.get('accessToken') or a.get('token', '')
            if at:
                accounts.append({'name': a.get('name') or a.get('uid', 'env'),
                                 'accessToken': at,
                                 'deviceId': a.get('deviceId', '')})

    if not accounts:
        print('未找到任何账号。')
        return 1

    results = []
    for acc in accounts:
        r = query_credits(acc['accessToken'], acc.get('deviceId', ''))
        r['name'] = acc['name']
        results.append(r)
        if args.json:
            continue
        if r.get('ok'):
            print('  %-12s 已用: %6d | 剩余: %6d' % (acc['name'], r['used'], r['available']))
        else:
            print('  %-12s 查询失败: %s' % (acc['name'], r.get('status', '')))

    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
