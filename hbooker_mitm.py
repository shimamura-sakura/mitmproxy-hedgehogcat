#!/bin/env python3
from hashlib import sha256
from typing import cast, Any
from Crypto.Cipher import AES
from os import path, makedirs
from base64 import b64decode, b64encode
from json import loads, dumps, dump, load as json_load

EDITSTATUS = True
SAVEPREFIX = ('hbkmitm',)
HOSTLIST = ('app1.happybooker.cn', 'app1.hbooker.com')
DEFAULTKEY = b'sD6doAOcW7hm7iaeK6UlcdtAIWlZGlBr'
HBOOKERIV = b'\0'*16


def hbkdec(data: bytes, key: bytes = DEFAULTKEY):
    aes_key = sha256(key).digest()
    aes = AES.new(aes_key, AES.MODE_CBC, HBOOKERIV)  # type: ignore CbcMode
    dat = aes.decrypt(b64decode(data))
    return dat[:-dat[-1]]


def hbkenc(data: bytes, key: bytes = DEFAULTKEY):
    aes_key = sha256(key).digest()
    aes = AES.new(aes_key, AES.MODE_CBC, HBOOKERIV)  # type: ignore CbcMode
    dat = data + chr(pad := 16 - len(data) % 16).encode('ascii') * pad
    return b64encode(aes.encrypt(dat))


def hbkdecj(data: bytes, key: bytes = DEFAULTKEY):
    return loads(str(hbkdec(data, key), 'utf-8'))


def hbkencj(data: Any, key: bytes = DEFAULTKEY):
    return hbkenc(bytes(dumps(data, separators=(',', ':')), 'utf-8'), key)


def loadj(name: str):
    try:
        with open(path.join(*SAVEPREFIX, name+'.json'), 'r', encoding='utf-8') as f:
            return json_load(f)
    except FileNotFoundError:
        return None


def savej(name: str, data: Any):
    with open(path.join(*SAVEPREFIX, name+'.json'), 'w', encoding='utf-8') as f:
        dump(data, f, ensure_ascii=False, indent='\t')


if __name__ == '__main__':
    # standalone create book from saved files
    from sys import argv, stderr
    match argv:
        case (_, book_id):
            out_file = f'book_{book_id}.txt'
        case (_, book_id, out_file):
            pass
        case _:
            print('用法: 本程序 <书籍ID> [输出文件名="book_{书籍ID}.txt"]')
            exit(1)
    print(f'书籍ID: {book_id} 输出文件: {out_file}')
    with open(out_file, 'w', encoding='utf-8') as f:
        # from sys import stdout as f
        if not (book_info := loadj(f'bookinfo-{book_id}')):
            stderr.write(f'书籍ID {book_id} 的书籍信息(bookinfo)不存在\n'
                         f'进入一次书籍详情可获得, 若下架请从别处补全\n')
            f.write('<缺少bookinfo, 请获得后重新生成或从别处补全>\n\n')
        else:
            b = book_info['book_info']
            a = book_info['up_reader_info']
            f.write(f'''== 基本信息 ==

书名: {b['book_name']} ({book_id})
作者: {b['author_name']} (用户: {a['reader_name']} ({a['reader_id']}))
标签: {b['tag']}
字数: {b['total_word_count']}
封面: {b['cover']}
上传时间: {b['newtime']}
更新时间: {b['uptime']}

== 简介 ==

{(b['description'] or '<简介为空>').rstrip()}\n\n''')
        bodylines: list[str] = ['\n== 正文 ==\n\n']
        if not (div0 := loadj(f'div-0-book-{book_id}')):
            stderr.write(f'书籍ID {book_id} 的目录(div-0)不存在\n')
            exit(1)
        else:
            f.write('== 目录 ==\n\n')
            for div in div0['chapter_list']:
                f.write(divline := f'# {div['division_name']}\n')
                bodylines.append(divline)
                bodylines.append('\n')
                for ch in div['chapter_list']:
                    f.write('  '+(chline := '- ' + ch['chapter_title']))
                    if (c := loadj(f'chapterdl-{ch['chapter_id']}')):
                        txtc = c['txt_content']
                        asay = c['author_say']
                    elif (c := loadj(f'chapter-{ch['chapter_id']}')):
                        c = c['chapter_info']
                        txtc = c['txt_content']
                        asay = c['author_say']
                        if c['is_paid'] == '1' and c['auth_access'] == '0':
                            txtc = '<用户未购买，仅预览部分>\n'+txtc
                    else:
                        f.write(txtc := '<文件缺失>')
                        asay = ''
                    f.write('\n')
                    bodylines.append(chline)
                    bodylines.append('\n\n')
                    bodylines.append(txtc.rstrip())
                    bodylines.append('\n\n')
                    if asay:
                        bodylines.append('== 作者说 ==\n\n')
                        bodylines.append(asay.rstrip())
                        bodylines.append('\n\n')
        f.writelines(bodylines)
else:
    # mitmproxy addon for happybooker/ciweimao
    from logging import info
    from zlib import decompress
    from mitmproxy.addonmanager import Loader
    from mitmproxy.http import HTTPFlow, Request, Response
    from mitmproxy.contentviews import Contentview, Metadata, add as cv_add

    def isapi(req: Request, res: Response):
        if req.pretty_host not in HOSTLIST:
            return False
        if 'content-type' not in res.headers:
            return False
        if not cast(str, res.headers['content-type']).startswith('text/plain'):
            return False
        if not res.content:
            return False
        return True

    class HBookerView(Contentview):
        def render_priority(self, data: bytes, metadata: Metadata) -> float:
            if not isinstance(metadata.flow, HTTPFlow):
                return -1
            if not metadata.flow.response:
                return -1
            if not isapi(metadata.flow.request, metadata.flow.response):
                return -1
            if not str(metadata.content_type).startswith('text/plain'):
                return -1
            return 1

        def prettify(self, data: bytes, metadata: Metadata) -> str:
            if not isinstance(metadata.flow, HTTPFlow):
                return 'Error: must be an HTTP flow'
            if not (res := metadata.flow.response):
                return 'Error: must have response'
            if not res.content:
                return 'Error: must have content'
            req = metadata.flow.request
            form = req.urlencoded_form
            jobj = hbkdecj(res.content)
            if (ccmd := form.get('chapter_command')):
                ccmd = bytes(ccmd, 'ascii')
                match jobj.get('data'):
                    case {'chapter_info': {'txt_content': str(ctxt)}}:
                        if not ctxt.startswith('http'):
                            ctxt = str(hbkdec(bytes(ctxt, 'ascii'), ccmd), 'utf-8')
                            jobj['data']['chapter_info']['txt_content'] = ctxt
                    case {'chapter_infos': str(cifs)}:
                        cifs = hbkdecj(bytes(cifs, 'ascii'), ccmd)
                        jobj['data']['chapter_infos'] = cifs
                    case _: pass
            return dumps(jobj, ensure_ascii=False, indent='\t')

    class HBookerAddon:
        def __init__(self):
            self.memo: dict[str, Any] = {}  # url -> { chapter_info }

        def load(self, loader: Loader):
            makedirs(path.join(*SAVEPREFIX), exist_ok=True)

        def response(self, flow: HTTPFlow):
            assert (req := flow.request) and (res := flow.response)
            if (jdat := self.memo.get(req.pretty_url)) is not None:
                assert res.content, '章节TXT链接应有内容'
                del self.memo[turl := req.pretty_url]
                cinf = jdat['chapter_info']
                chid = cinf['chapter_id']
                info(f'章节TXT: {chid} {cinf['chapter_title']} <-> {turl}')
                ctxt = str(decompress(res.content), 'utf-8')
                ctxt = ctxt.replace('<p>', '').replace('</p>', '\n')
                cinf['txt_content'] = ctxt
                savej(f'chapter-{chid}', jdat)
            if not isapi(req, res):
                return
            assert res.content
            form = req.urlencoded_form  # request arguments
            match req.path_components:
                case ('bookshelf', 'get_shelf_book_list_new') if EDITSTATUS:
                    edit = False
                    jobj = hbkdecj(res.content)
                    for o in jobj['data']['book_list']:
                        if str((b := o['book_info']).get('update_status')) == '2':
                            info(f'{b['book_id']} {b['book_name']!r} 下架')
                            b['update_status'] = '1'
                            edit = True
                    if edit:
                        info('修改下架书籍状态为完结')
                        res.content = hbkencj(jobj)
                case ('book', 'get_info_by_id'):
                    jdat = hbkdecj(res.content)['data']
                    bkif = jdat['book_info']
                    bkid = bkif['book_id']
                    info(f'书籍信息: {bkid} - {bkif['book_name']}')
                    savej(f'bookinfo-{bkid}', jdat)
                case ('book', 'get_division_list'):
                    jdat = hbkdecj(res.content)['data']
                    bkid = form['book_id']
                    info(f'书籍分卷列表: {bkid}')
                    savej(f'bookdivs-{bkid}', jdat)
                case ('chapter', 'get_cpt_ifm'):
                    xmsg = ''
                    jdat = hbkdecj(res.content)['data']
                    chid = form['chapter_id']
                    cinf = jdat['chapter_info']
                    if cinf['is_paid'] == '1' and cinf['auth_access'] == '0':
                        xmsg = ' (未购买，仅有预览部分)'
                    info(f'章节: {chid} - {cinf['chapter_title']}{xmsg}')
                    ctxt = cast(str, cinf['txt_content'])
                    ckey = bytes(form['chapter_command'], 'ascii')
                    if ctxt.startswith('http'):  # cdn url
                        info(f'章节 {chid} <-- {ctxt}')
                        self.memo[ctxt] = jdat
                    else:
                        btxt = hbkdec(bytes(ctxt, 'ascii'), ckey)
                        cinf['txt_content'] = str(btxt, 'utf-8')
                    savej(f'chapter-{chid}', jdat)
                case ('chapter', 'download_cpt'):
                    ckey = bytes(form['chapter_command'], 'ascii')
                    cifs = hbkdecj(res.content)['data']['chapter_infos']
                    cifs = hbkdecj(bytes(cifs, 'ascii'), ckey)
                    info(f'下载多章节: {form['chapter_id']}')
                    for i, chif in enumerate(cifs):
                        chid = chif['chapter_id']
                        info(f'[{i:2}] 下载多章节: {chid}')
                        savej(f'chapterdl-{chid}', chif)
                case ('chapter', 'get_updated_chapter_by_division_new'):
                    bkid = form['book_id']
                    dvid = form['division_id']
                    jdat = hbkdecj(res.content)['data']
                    info(f'书籍分卷(新): 书 {bkid} - 卷 {dvid}')
                    savej(f'div-{dvid}-book-{bkid}', jdat)
                case _: pass
    cv_add(HBookerView)
    addons = [HBookerAddon()]
