#!/usr/bin/python3
"""
auto-vuln-scan.py - 指纹→漏洞自动映射扫描器
识别技术栈后自动测试已知漏洞路径

用法:
  python3 auto-vuln-scan.py https://target.cuit.edu.cn
  python3 auto-vuln-scan.py https://oa.cuit.edu.cn --all
  python3 auto-vuln-scan.py alive.txt --batch 5          # 批量扫描
  python3 auto-vuln-scan.py alive.txt -o vulns.json --json

原理: 先做指纹识别(响应头+页面内容), 匹配已知产品, 然后自动测试该产品的已知漏洞路径
"""

import subprocess
import os
import re
import json
import argparse
try:
    import httpx
except ImportError:
    httpx = None

SCRIPTS_DIR = "/root/.hermes/scripts"


# ============================================================
# 漏洞指纹库
# ============================================================
FINGERPRINT_DB = {
    'seeyon_oa': {
        'name': '致远OA',
        'match': {
            'headers': [r'seeyon', r'V\d+_\d+SP\d+', r'_ctpSkinUrl'],
            'body': [r'seeyon', r'致远', r'A8N', r'A8\+'],
            'cookies': [r'JSESSIONID'],
        },
        'paths': [
            ('/seeyon/rest/token', 'GET', 'REST Token未授权', 'medium',
             lambda b: 'code' in b and '1010' not in b),
            ('/seeyon/rest/orgMember', 'GET', 'REST组织成员泄露', 'medium',
             lambda b: 'code' not in b and len(b) > 100),
            ('/seeyon/rest/organization', 'GET', 'REST组织架构泄露', 'medium',
             lambda b: 'code' not in b and len(b) > 100),
            ('/seeyon/rest/department', 'GET', 'REST部门信息泄露', 'medium',
             lambda b: 'code' not in b and len(b) > 100),
            ('/seeyon/thirdpartyController.do', 'GET', 'thirdpartyController可访问', 'low',
             lambda b: len(b) < 10),  # 200空响应可能有用
            ('/seeyon/autoinstall.do', 'GET', 'autoinstall未授权', 'medium',
             lambda b: '被迫下线' not in b and len(b) > 100),
            ('/seeyon/downloadServlet', 'GET', 'downloadServlet任意文件下载', 'high',
             lambda b: '被迫下线' not in b and len(b) > 100),
            ('/seeyon/fileUpload.do', 'GET', 'fileUpload未授权', 'medium',
             lambda b: '被迫下线' not in b and len(b) > 100),
            ('/seeyon/rest/authentication', 'POST', 'REST认证接口', 'medium',
             lambda b: '被迫下线' not in b and 'code' in b),
        ],
    },
    'cas_authserver': {
        'name': 'CAS统一认证',
        'match': {
            'headers': [r'authserver', r'YWTBSESSIONID'],
            'body': [r'authserver', r'一网通办', r'CAS', r'loginType=cas'],
            'cookies': [r'YWTBSESSIONID'],
        },
        'paths': [
            ('/api/base/login', 'POST', '登录接口用户枚举', 'medium',
             lambda b: '账号不存在' in b or '登录失败' in b),
            ('/api/base/apps', 'GET', '应用列表未授权访问', 'medium',
             lambda b: '"roles"' in b and '"apps"' in b),
            ('/api/base/stats/dept', 'GET', '部门统计信息泄露', 'medium',
             lambda b: '"deptName"' in b and '"deptId"' in b),
            ('/api/base/register/config', 'GET', '注册配置泄露', 'low',
             lambda b: '"anonymous"' in b and '"registerType"' in b),
            ('/api/base/wx/qr_code', 'GET', '微信AppID泄露', 'low',
             lambda b: '"appid"' in b),
            ('/api/base/config', 'GET', '系统配置泄露', 'low',
             lambda b: '"copyInfo"' in b),
            ('/api/base/index_apps', 'GET', '完整应用配置泄露', 'medium',
             lambda b: '"roles"' in b and len(b) > 10000),
            ('/api/base/retrieve/check', 'POST', '密码重置用户枚举', 'medium',
             lambda b: '登录账号不存在' in b),
        ],
        'user_enum': {
            'endpoint': '/api/base/login',
            'method': 'POST',
            'body': '{"username":"%USER%","password":"test"}',
            'exists_msg': '登录失败',
            'notexists_msg': '账号不存在',
        },
    },
    'spring_boot': {
        'name': 'Spring Boot',
        'match': {
            'headers': [r'spring', r'X-Application-Context'],
            'body': [r'Whitelabel Error Page', r'Spring'],
        },
        'paths': [
            ('/actuator', 'GET', 'Actuator端点暴露', 'high',
             lambda b: '"_links"' in b or 'status' in b),
            ('/actuator/health', 'GET', 'Actuator健康信息泄露', 'medium',
             lambda b: '"status"' in b),
            ('/actuator/env', 'GET', 'Actuator环境变量泄露', 'high',
             lambda b: '"propertySources"' in b or '"activeProfiles"' in b),
            ('/actuator/mappings', 'GET', 'Actuator映射信息泄露', 'medium',
             lambda b: '"handler"' in b or 'mappings' in b),
            ('/actuator/heapdump', 'GET', 'Actuator堆转储(内存泄露)', 'critical',
             lambda b: len(b) > 10000),
            ('/actuator/configprops', 'GET', 'Actuator配置泄露', 'high',
             lambda b: '"propertySources"' in b),
            ('/actuator/threaddump', 'GET', 'Actuator线程转储', 'medium',
             lambda b: '"threadName"' in b),
            ('/env', 'GET', '环境变量泄露', 'high',
             lambda b: '"propertySources"' in b),
            ('/mappings', 'GET', 'URL映射泄露', 'medium',
             lambda b: '"handler"' in b),
        ],
    },
    'druid_monitor': {
        'name': 'Druid监控',
        'match': {
            'body': [r'druid', r'DruidStatView'],
        },
        'paths': [
            ('/druid/', 'GET', 'Druid监控页面', 'medium',
             lambda b: 'druid' in b.lower() and 'login' in b.lower()),
            ('/druid/login.html', 'GET', 'Druid登录页', 'low',
             lambda b: 'druid' in b.lower()),
            ('/druid/datasource.json', 'GET', 'Druid数据源泄露', 'high',
             lambda b: '"DbType"' in b or '"URL"' in b),
            ('/druid/sql.json', 'GET', 'Druid SQL监控泄露', 'medium',
             lambda b: '"SQL"' in b),
            ('/druid/wall.json', 'GET', 'Druid防火墙信息', 'medium',
             lambda b: '"CheckCount"' in b),
        ],
    },
    'swagger': {
        'name': 'Swagger UI',
        'match': {
            'body': [r'swagger', r'Swagger UI', r'api-docs'],
        },
        'paths': [
            ('/swagger-ui.html', 'GET', 'Swagger UI暴露', 'medium',
             lambda b: 'swagger' in b.lower()),
            ('/swagger-ui/', 'GET', 'Swagger UI v3暴露', 'medium',
             lambda b: 'swagger' in b.lower()),
            ('/v2/api-docs', 'GET', 'API文档泄露', 'high',
             lambda b: '"paths"' in b and '"swagger"' in b),
            ('/v3/api-docs', 'GET', 'OpenAPI 3.0文档泄露', 'high',
             lambda b: '"paths"' in b and '"openapi"' in b),
            ('/api-docs', 'GET', 'API文档泄露', 'high',
             lambda b: '"paths"' in b),
        ],
    },
    'weaver_ecology': {
        'name': '泛微OA',
        'match': {
            'body': [r'ecology', r'泛微', r'e-cology', r'_wev8'],
            'cookies': [r'ecology_JSessionid'],
        },
        'paths': [
            ('/api/ec/dev/codedatas/getAll', 'GET', '泛微代码数据泄露', 'medium',
             lambda b: '"code"' in b and '"name"' in b),
            ('/rest/wx/api/getWxAppConfig', 'GET', '泛微微信配置泄露', 'medium',
             lambda b: '"appId"' in b or '"corpId"' in b),
            ('/wui/index.html', 'GET', '泛微入口页面', 'low',
             lambda b: 'ecology' in b.lower()),
        ],
    },
    'wisedu_cas': {
        'name': '金智教育CAS',
        'match': {
            'body': [r'wisedu', r'金智', r'lyuapServer', r'pwdDefaultEncryptSalt'],
            'cookies': [r'CASTGC'],
        },
        'paths': [
            ('/authserver/getEncryptInfo', 'GET', '金智CAS密钥泄露', 'high',
             lambda b: 'pwdDefaultEncryptSalt' in b),
            ('/authserver/needCaptcha.html', 'GET', '金智CAS验证码检查', 'medium',
             lambda b: '"data"' in b),
            ('/authserver/serviceRegister', 'GET', '金智CAS服务注册', 'medium',
             lambda b: 'service' in b.lower()),
        ],
    },
    'visual_sitebuilder': {
        'name': 'Visual SiteBuilder',
        'match': {
            'body': [r'Visual SiteBuilder', r'_sitegray', r'vsbscreen'],
        },
        'paths': [
            ('/_sitegray/_sitegray.js', 'GET', 'VSB配置文件', 'low',
             lambda b: len(b) > 50),
            ('/system/resource/js/vsbscreen.min.js', 'GET', 'VSB脚本暴露', 'low',
             lambda b: len(b) > 50),
        ],
    },
    'shiro': {
        'name': 'Apache Shiro',
        'match': {
            'cookies': [r'rememberMe'],
        },
        'paths': [
            ('/', 'GET', 'Shiro rememberMe Cookie', 'info',
             lambda b: True),  # 已通过cookie匹配
        ],
    },
    'sangfor_webvpn': {
        'name': 'Sangfor EasyConnect WebVPN',
        'match': {
            'body': [r'login_psw\.csp', r'TWFID', r'Sangfor', r'EasyConnect'],
            'cookies': [r'TWFID'],
        },
        'paths': [
            ('/por/login_psw.csp', 'POST', 'WebVPN登录用户枚举', 'medium',
             lambda b: 'ErrorCode' in b),
            ('/por/login_key.csp', 'GET', 'WebVPN密钥登录泄露', 'low',
             lambda b: 'DKEY_TYPE' in b),
            ('/por/conf/cert_status.csp', 'GET', 'WebVPN证书状态', 'medium',
             lambda b: 'cert' in b.lower()),
        ],
    },
    'tomcat': {
        'name': 'Apache Tomcat',
        'match': {
            'headers': [r'Tomcat', r'Apache-Coyote'],
            'body': [r'Apache Tomcat'],
        },
        'paths': [
            ('/manager/html', 'GET', 'Tomcat管理页面', 'high',
             lambda b: '401' in b or 'tomcat' in b.lower()),
            ('/host-manager/html', 'GET', 'Tomcat主机管理', 'high',
             lambda b: '401' in b),
        ],
    },
    'yonyou_u8_nc': {
        'name': '用友U8/NC',
        'match': {
            'headers': ["(?i)Server:.*(Yonyou|u8c|uap|nccloud)", "(?i)X-Powered-By:.*(UAP|Yonyou)"],
            'body': ["\u7528\u53cbU8", "\u7528\u53cb\u7f51\u7edc", "Yonyou", "NCCloud", "uap\\.desktop", "iuap"],
            'cookies': ["(?i)(JSESSIONID|U8C|NCSESSIONID|uap_locale)="],
        },
        'paths': [
            ('/u8cloud/', 'GET', 'U8 Cloud入口识别', 'info', lambda b: len(b) > 100),
            ('/nccloud/resources/uap/rbac/login/main/index.html', 'GET', 'NC Cloud登录页识别', 'info', lambda b: len(b) > 100),
            ('/service/', 'GET', '用友服务目录探测', 'low', lambda b: len(b) > 100),
            ('/uapws/', 'GET', 'UAP WebService入口识别', 'low', lambda b: len(b) > 100),
        ],
    },
    'kingdee_cloud_galaxy': {
        'name': '金蝶云星空',
        'match': {
            'headers': ["(?i)Server:.*(Kingdee|K3Cloud|BOS)", "(?i)X-Powered-By:.*ASP\\.NET"],
            'body': ["\u91d1\u8776\u4e91\u661f\u7a7a", "Kingdee", "K3Cloud", "BOS", "kdservice", "HTML5Client"],
            'cookies': ["(?i)(ASP\\.NET_SessionId|kdservice-sessionid|KDSVC)="],
        },
        'paths': [
            ('/K3Cloud/', 'GET', '金蝶云星空主入口识别', 'info', lambda b: len(b) > 100),
            ('/K3Cloud/HTML5/index.aspx', 'GET', 'HTML5客户端入口识别', 'info', lambda b: len(b) > 100),
            ('/K3Cloud/Silverlight/Index.aspx', 'GET', '旧版客户端入口识别', 'low', lambda b: len(b) > 100),
            ('/K3Cloud/Kingdee.BOS.WebApi.ServicesStub.AuthService.ValidateUser.common.kdsvc', 'GET', 'WebAPI服务端点存在性识别', 'info', lambda b: '{' in b),
        ],
    },
    'landray_oa': {
        'name': '蓝凌OA',
        'match': {
            'headers': ["(?i)Server:.*(Landray|EKP|Tomcat)", "(?i)X-Powered-By:.*JSP"],
            'body': ["\u84dd\u51cc", "Landray", "EKP", "LKS", "sys/ui/extend", "km/review"],
            'cookies': ["(?i)(JSESSIONID|LtpaToken|ekp_locale)="],
        },
        'paths': [
            ('/ekp/login.jsp', 'GET', '蓝凌EKP登录入口识别', 'info', lambda b: len(b) > 100),
            ('/sys/ui/extend/theme/default/style/icon.jsp', 'GET', '主题资源入口识别', 'info', lambda b: len(b) > 100),
            ('/admin.do', 'GET', '管理路由存在性识别', 'low', lambda b: len(b) > 100),
            ('/third/pda/login.jsp', 'GET', '移动端登录入口识别', 'low', lambda b: len(b) > 100),
        ],
    },
    'tongda_oa': {
        'name': '通达OA',
        'match': {
            'headers': ["(?i)Server:.*(nginx|Apache|TDOA)", "(?i)X-Powered-By:.*PHP"],
            'body': ["\u901a\u8fbeOA", "Office Anywhere", "Tongda", "general/login_code", "ispirit", "MYOA"],
            'cookies': ["(?i)(PHPSESSID|OA_USER_ID|SID_[0-9a-f]+)="],
        },
        'paths': [
            ('/login.php', 'GET', '通达OA登录入口识别', 'info', lambda b: len(b) > 100),
            ('/general/index.php', 'GET', '通达OA业务首页入口识别', 'info', lambda b: len(b) > 100),
            ('/ispirit/login_code.php', 'GET', '移动/即时通讯验证码入口识别', 'low', lambda b: len(b) > 100),
            ('/static/templates/2013_01/index.css', 'GET', '默认模板静态资源识别', 'info', lambda b: len(b) > 100),
        ],
    },
    'inspur_gs': {
        'name': '浪潮GS',
        'match': {
            'headers': ["(?i)Server:.*(Inspur|Tomcat|WebLogic)", "(?i)X-Powered-By:.*(Servlet|JSP)"],
            'body': ["\u6d6a\u6f6eGS", "Inspur", "GSCloud", "cwbase", "iGIX", "Genersoft"],
            'cookies': ["(?i)(JSESSIONID|gs_session|cwbase_locale)="],
        },
        'paths': [
            ('/cwbase/', 'GET', '浪潮GS基础平台入口识别', 'info', lambda b: len(b) > 100),
            ('/cwbase/web/Login.jsp', 'GET', '浪潮GS登录页识别', 'info', lambda b: len(b) > 100),
            ('/gscloud/', 'GET', 'GS Cloud入口识别', 'info', lambda b: len(b) > 100),
            ('/eai/', 'GET', '企业应用集成入口识别', 'low', lambda b: len(b) > 100),
        ],
    },
    'zfsoft_jw': {
        'name': '正方教务',
        'match': {
            'headers': ["(?i)Server:.*(Tomcat|Apache|nginx)", "(?i)X-Powered-By:.*(JSP|Servlet)"],
            'body': ["\u6b63\u65b9", "ZFSoft", "\u6559\u52a1\u7ba1\u7406\u7cfb\u7edf", "jwglxt", "jsxsd", "xtgl/login_slogin"],
            'cookies': ["(?i)(JSESSIONID|route|SERVERID)="],
        },
        'paths': [
            ('/jwglxt/xtgl/login_slogin.html', 'GET', '正方新版教务登录入口识别', 'info', lambda b: len(b) > 100),
            ('/jsxsd/', 'GET', '正方旧版教务入口识别', 'info', lambda b: len(b) > 100),
            ('/jwglxt/xtgl/index_initMenu.html', 'GET', '教务菜单初始化入口存在性识别', 'low', lambda b: len(b) > 100),
            ('/jwglxt/kaptcha', 'GET', '验证码接口识别', 'info', lambda b: True),
        ],
    },
    'qiangzhi_jw': {
        'name': '强智教务',
        'match': {
            'headers': ["(?i)Server:.*(Tomcat|Apache|nginx)", "(?i)X-Powered-By:.*(JSP|Servlet)"],
            'body': ["\u5f3a\u667a", "QiangZhi", "\u6559\u5b66\u7efc\u5408\u4fe1\u606f\u670d\u52a1\u5e73\u53f0", "jwxt", "xk/LoginToXk", "qzjw"],
            'cookies': ["(?i)(JSESSIONID|SERVERID|qz_session)="],
        },
        'paths': [
            ('/jwxt/', 'GET', '强智教务系统入口识别', 'info', lambda b: len(b) > 100),
            ('/jwxt/Logon.do?method=logon', 'GET', '强智登录路由识别', 'info', lambda b: len(b) > 100),
            ('/jwxt/verifycode.servlet', 'GET', '验证码接口识别', 'info', lambda b: True),
            ('/jwxt/xk/LoginToXk', 'GET', '选课模块入口识别', 'low', lambda b: len(b) > 100),
        ],
    },
    'kingosoft_jw': {
        'name': '青果教务',
        'match': {
            'headers': ["(?i)Server:.*(IIS|ASP\\.NET|nginx)", "(?i)X-Powered-By:.*ASP\\.NET"],
            'body': ["\u9752\u679c", "KINGOSOFT", "Kingosoft", "\u6559\u52a1\u7f51\u7edc\u7ba1\u7406\u7cfb\u7edf", "jwweb", "ZNPK"],
            'cookies': ["(?i)(ASP\\.NET_SessionId|JSESSIONID|kingo)="],
        },
        'paths': [
            ('/jwweb/', 'GET', '青果教务入口识别', 'info', lambda b: len(b) > 100),
            ('/jwweb/default.aspx', 'GET', '青果教务默认登录页识别', 'info', lambda b: len(b) > 100),
            ('/ZNPK/Private/List_Xnxq.aspx', 'GET', '排课模块学年学期页面存在性识别', 'low', lambda b: len(b) > 100),
            ('/jwweb/sys/ValidateCode.aspx', 'GET', '验证码接口识别', 'info', lambda b: True),
        ],
    },
    'wisedu': {
        'name': '金智教育Wisedu',
        'match': {
            'headers': ["(?i)Server:.*(Wisedu|nginx|Tomcat)", "(?i)X-Powered-By:.*(Wisedu|Java|JSP)"],
            'body': ["\u91d1\u667a\u6559\u80b2", "Wisedu", "\u667a\u6167\u6821\u56ed", "ehall", "amp-auth", "cas/login"],
            'cookies': ["(?i)(JSESSIONID|MOD_AUTH_CAS|iPlanetDirectoryPro|route)="],
        },
        'paths': [
            ('/ehall/', 'GET', '网上办事大厅入口识别', 'info', lambda b: len(b) > 100),
            ('/amp-auth-adapter/login', 'GET', '统一认证适配登录入口识别', 'info', lambda b: len(b) > 100),
            ('/cas/login', 'GET', 'CAS统一认证入口识别', 'info', lambda b: len(b) > 100),
            ('/publicapp/sys/itpub/MobileCommon/getMenuInfo.do', 'GET', '公共应用菜单接口存在性识别', 'low', lambda b: '{' in b),
        ],
    },
    'shuwei_jw': {
        'name': '树维教务',
        'match': {
            'headers': ["(?i)Server:.*(Tomcat|nginx|Apache)", "(?i)X-Powered-By:.*(JSP|Servlet)"],
            'body': ["\u6811\u7ef4", "ShuWei", "\u6559\u5b66\u7ba1\u7406\u4fe1\u606f\u670d\u52a1\u5e73\u53f0", "swjw", "student/login", "jwgl"],
            'cookies': ["(?i)(JSESSIONID|SERVERID|sw_session)="],
        },
        'paths': [
            ('/swjw/', 'GET', '树维教务入口识别', 'info', lambda b: len(b) > 100),
            ('/student/login', 'GET', '学生端登录入口识别', 'info', lambda b: len(b) > 100),
            ('/teacher/login', 'GET', '教师端登录入口识别', 'info', lambda b: len(b) > 100),
            ('/jwgl/', 'GET', '教务管理入口识别', 'info', lambda b: len(b) > 100),
        ],
    },
    'nginx_status': {
        'name': 'Nginx',
        'match': {
            'headers': [r'nginx'],
        },
        'paths': [
            ('/nginx_status', 'GET', 'Nginx状态页', 'medium',
             lambda b: 'Active connections' in b),
            ('/server-status', 'GET', 'Server Status', 'medium',
             lambda b: 'Apache Server Status' in b),
        ],
    },
}

# 用户枚举测试模板
USER_ENUM_TESTS = {
    'cas_authserver': {
        'endpoint': '/api/base/login',
        'method': 'POST',
        'headers': {'Content-Type': 'application/json'},
        'body_tpl': '{"username":"%USER%","password":"TestPass123!"}',
        'users': ['admin', 'test', 'root', 'administrator', 'manager',
                  '2021001', '2022001', '2023001', '2024001',
                  '20210001', '20220001', '20230001', '20240001',
                  'faculty', 'student', 'admin1', 'test1'],
        'exists_indicators': ['登录失败', '微信扫码', '校园网外', '密码错误', '验证码'],
        'notexists_indicators': ['账号不存在', '用户不存在', '用户名不存在'],
    },
}


def fetch_target(url, timeout=6):
    """获取目标响应"""
    if httpx:
        try:
            client = httpx.Client(verify=False, timeout=timeout, follow_redirects=True)
            resp = client.get(url)
            headers = '\n'.join(f'{k}: {v}' for k, v in resp.headers.items())
            return headers, resp.text
        except Exception:
            return '', ''
    else:
        try:
            cmd = ['curl', '-sk', '--max-time', str(timeout), '-D', '/dev/stderr', url]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
            return r.stderr, r.stdout
        except Exception:
            return '', ''


def match_fingerprint(headers, body, url):
    """匹配指纹"""
    matches = []
    h_lower = headers.lower()
    b_lower = body.lower()
    cookies = headers

    for fid, fdef in FINGERPRINT_DB.items():
        score = 0
        match_details = []

        # 匹配headers
        for pattern in fdef['match'].get('headers', []):
            if re.search(pattern, headers, re.IGNORECASE):
                score += 2
                match_details.append(f'header:{pattern}')

        # 匹配body
        for pattern in fdef['match'].get('body', []):
            if re.search(pattern, body, re.IGNORECASE):
                score += 2
                match_details.append(f'body:{pattern}')

        # 匹配cookies
        for pattern in fdef['match'].get('cookies', []):
            if re.search(pattern, cookies, re.IGNORECASE):
                score += 3
                match_details.append(f'cookie:{pattern}')

        if score > 0:
            matches.append((fid, fdef['name'], score, match_details))

    return sorted(matches, key=lambda x: -x[2])


def test_vuln_path(base_url, path, method, timeout=6):
    """测试单个漏洞路径"""
    url = base_url.rstrip('/') + path
    if httpx:
        try:
            client = httpx.Client(verify=False, timeout=timeout, follow_redirects=True)
            if method == 'POST':
                resp = client.post(url, json={"test": "probe"})
            else:
                resp = client.get(url)
            return str(resp.status_code), str(len(resp.content)), resp.text
        except Exception:
            return '000', '0', ''
    else:
        try:
            if method == 'POST':
                cmd = ['curl', '-sk', '--max-time', str(timeout), '-X', 'POST',
                       '-H', 'Content-Type: application/json', '-d', '{"test":"probe"}',
                       '-o', '/tmp/auto_vuln_body', '-w', '%{http_code}|%{size_download}', url]
            else:
                cmd = ['curl', '-sk', '--max-time', str(timeout),
                       '-o', '/tmp/auto_vuln_body', '-w', '%{http_code}|%{size_download}', url]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
            parts = r.stdout.strip().split('|')
            code = parts[0] if parts else '000'
            size = parts[1] if len(parts) > 1 else '0'
            body = ''
            try:
                with open('/tmp/auto_vuln_body', 'r', errors='ignore') as f:
                    body = f.read()
            except Exception:
                pass
            return code, size, body
        except Exception:
            return '000', '0', ''


def test_user_enum(base_url, enum_config, timeout=6):
    """用户枚举测试"""
    url = base_url.rstrip('/') + enum_config['endpoint']
    results = {}

    for user in enum_config['users']:
        body = enum_config['body_tpl'].replace('%USER%', user)
        try:
            cmd = [
                'curl', '-sk', '--max-time', str(timeout),
                '-X', enum_config['method'],
            ]
            for k, v in enum_config.get('headers', {}).items():
                cmd.extend(['-H', f'{k}: {v}'])
            cmd.extend([
                '-d', body,
                '-o', '/tmp/auto_enum_body',
                url
            ])

            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
            resp = ''
            try:
                with open('/tmp/auto_enum_body', 'r', errors='ignore') as f:
                    resp = f.read()
            except Exception:
                pass

            exists = any(ind in resp for ind in enum_config.get('exists_indicators', []))
            not_exists = any(ind in resp for ind in enum_config.get('notexists_indicators', []))

            if exists and not not_exists:
                results[user] = 'EXISTS'
            elif not_exists and not exists:
                results[user] = 'NOT_EXISTS'
            else:
                results[user] = f'UNKNOWN:{resp[:100]}'
        except Exception as e:
            results[user] = f'ERROR:{e}'

    return results


def scan_target(base_url, timeout=6, test_all=False, do_enum=False):
    """扫描单个目标"""
    print(f"\n{'='*60}")
    print(f"[*] Scanning: {base_url}")
    print(f"{'='*60}")

    # Step 1: 指纹识别
    headers, body = fetch_target(base_url, timeout)
    if not headers and not body:
        print(f"[-] Target unreachable: {base_url}")
        return []

    matches = match_fingerprint(headers, body, base_url)
    if not matches:
        print(f"[!] No fingerprint matched for {base_url}")
        print(f"    Server: {headers.split('Server:')[1].split(chr(10))[0].strip() if 'Server:' in headers else 'unknown'}")
        return []

    print("[+] Fingerprint matches:")
    for fid, name, score, details in matches:
        print(f"    {name} (score={score}): {', '.join(details)}")

    # Step 2: 漏洞路径测试
    vulns = []
    for fid, name, score, details in matches:
        fdef = FINGERPRINT_DB[fid]
        print(f"\n[*] Testing {name} vulnerability paths...")

        for path, method, desc, severity, is_vuln in fdef['paths']:
            code, size, body = test_vuln_path(base_url, path, method, timeout)

            if code in ('000',):
                status = 'TIMEOUT'
            elif code in ('404', '405'):
                status = 'NOT_FOUND'
            elif code in ('301', '302'):
                status = 'REDIRECT'
            elif code in ('401', '403'):
                status = 'AUTH_REQUIRED'
            elif code == '200':
                if is_vuln(body):
                    status = 'VULNERABLE'
                    vulns.append({
                        'url': base_url + path,
                        'method': method,
                        'description': desc,
                        'severity': severity,
                        'code': code,
                        'size': size,
                        'product': name,
                        'body_preview': body[:200],
                    })
                else:
                    status = 'SAFE'
            else:
                status = f'HTTP_{code}'

            icon = {
                'VULNERABLE': '!!!',
                'SAFE': '   ',
                'AUTH_REQUIRED': '   ',
                'NOT_FOUND': '   ',
                'REDIRECT': '   ',
                'TIMEOUT': '...',
            }.get(status, '   ')

            print(f"    [{icon}] {path} -> {code} {size}B [{status}] {desc}")

    # Step 3: 用户枚举测试
    if do_enum:
        for fid, name, score, details in matches:
            if fid in USER_ENUM_TESTS:
                print(f"\n[*] Testing user enumeration ({name})...")
                enum_config = USER_ENUM_TESTS[fid]
                enum_results = test_user_enum(base_url, enum_config, timeout)

                exists_users = [u for u, r in enum_results.items() if r == 'EXISTS']
                not_exists = [u for u, r in enum_results.items() if r == 'NOT_EXISTS']

                if exists_users:
                    print(f"    [!!!] Confirmed existing accounts: {', '.join(exists_users)}")
                    vulns.append({
                        'url': base_url + enum_config['endpoint'],
                        'method': enum_config['method'],
                        'description': f'用户枚举 - 确认存在账号: {", ".join(exists_users)}',
                        'severity': 'medium',
                        'product': name,
                        'confirmed_users': exists_users,
                    })
                else:
                    print(f"    [   ] No confirmed existing accounts (tested: {len(enum_results)})")

    # 总结
    print(f"\n[*] Summary for {base_url}:")
    print(f"    Products: {', '.join(m[1] for m in matches)}")
    print(f"    Vulnerabilities found: {len(vulns)}")
    for v in vulns:
        print(f"    [{v['severity'].upper()}] {v['description']}")
        print(f"           URL: {v['url']}")

    return vulns


def main():
    parser = argparse.ArgumentParser(description='Auto fingerprint → vulnerability scanner')
    parser.add_argument('target', help='URL or file with URLs')
    parser.add_argument('--timeout', type=int, default=6, help='Request timeout')
    parser.add_argument('--all', action='store_true', help='Test all paths regardless of severity')
    parser.add_argument('--enum', action='store_true', help='Test user enumeration')
    parser.add_argument('--output', '-o', help='Output file')
    parser.add_argument('--json', action='store_true', help='JSON output')
    parser.add_argument('--batch', type=int, default=1, help='Parallel targets (default: 1)')
    parser.add_argument('--workspace', help='Save results to workspace domain')
    args = parser.parse_args()

    # 确定目标列表
    if os.path.isfile(args.target):
        with open(args.target) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        # 确保有协议前缀
        targets = [t if t.startswith('http') else f'https://{t}' for t in targets]
    else:
        targets = [args.target if args.target.startswith('http') else f'https://{args.target}']

    print(f"[*] {len(targets)} target(s) to scan")

    all_vulns = []
    for target in targets:
        vulns = scan_target(target, args.timeout, args.all, args.enum)
        all_vulns.extend(vulns)

    # 输出
    print(f"\n{'='*60}")
    print(f"[*] TOTAL: {len(all_vulns)} vulnerabilities across {len(targets)} targets")
    print(f"{'='*60}")

    # 按严重性排序
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    all_vulns.sort(key=lambda v: severity_order.get(v.get('severity', 'info'), 5))

    for v in all_vulns:
        print(f"  [{v['severity'].upper():8s}] {v['description']}")
        print(f"           {v['url']}")

    if args.output:
        with open(args.output, 'w') as f:
            if args.json:
                json.dump(all_vulns, f, indent=2, ensure_ascii=False)
            else:
                for v in all_vulns:
                    f.write(f"[{v['severity'].upper()}] {v['description']}\n")
                    f.write(f"  URL: {v['url']}\n")
                    f.write(f"  Product: {v.get('product', 'unknown')}\n\n")
        print(f"\n[+] Results written to {args.output}")

    # 保存到workspace
    if args.workspace:
        import subprocess as sp
        for v in all_vulns:
            vjson = json.dumps(v, ensure_ascii=False)
            sp.run(['/usr/bin/python3', os.path.join(SCRIPTS_DIR, 'src-workspace.py'),
                    'add-vuln', args.workspace, '--json', vjson],
                   capture_output=True, timeout=10)
        print(f"[+] {len(all_vulns)} vulns saved to workspace: {args.workspace}")


if __name__ == '__main__':
    main()
