"""HTTP Client for Gas API."""

import logging
import requests
import json
import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Dict, Any
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

from .const import (
    API_BASE,
    API_SIGN_KEY,
    API_USER_AUTH,
    API_PASSWORD_LOGIN,
    API_GET_COMPANIES,
    API_GET_RSA_PUBLIC_KEY,
    API_CREATE_QR_CODE,
    API_CHECK_QR_STATUS,
    API_GET_USER_DEBT,
    API_GET_USER_DEBT_AUTH,
    API_GET_CUSTOMER_INFO,
    API_GET_METER_READING,
    API_GET_PAYMENT_RECORDS,
    API_GET_MONTHLY_VOLUME,
    API_REFRESH_TOKEN,
    API_GET_GAS_COMPANY_LIST,
    API_GET_USER_MESSAGE,
    API_GET_USER_GAS_VOLUME,
    API_GET_PAYMENT_RECORDS_HALL,
    PARAM_CID,
    PARAM_USER_CODE,
    PARAM_TERMINAL_TYPE,
    PARAM_USER_CODE_ID,
    PARAM_PAGE,
    PARAM_PAGE_SIZE,
    PARAM_PAGE_NUMBER,
    PARAM_CODE,
    PARAM_UNION_ID,
    PARAM_LOGIN_ID,
    PARAM_QR_CODE_DATA,
    PARAM_LENGTH_TIME_YQQS,
    PARAM_TIMESTAMP,
    DEFAULT_CID_NATIONWIDE,
    FIELD_CODE,
    FIELD_DATA,
    FIELD_MESSAGE,
    FIELD_SUCCESS,
    FIELD_SUCCESS_WITH_DATA,
    DATA_ACCOUNT_ID,
    DATA_ADDRESS,
    DATA_CUSTOMER_NAME,
    DATA_REMOTE_METER_BALANCE,
    DATA_METER_TYPE,
    DATA_MDM_CODE,
    DATA_READING_LAST_TIME,
    DATA_REMOTE_METER_LAST_COMMUNICATION_TIME,
    DATA_RATE_ITEM_INFO,
)
from .models import GasAccount, LadderPricing, CSGAPIError

_LOGGER = logging.getLogger(__name__)

# 公司列表缓存（cid -> {mdmCode, name}），进程内共享，避免重复拉取
_COMPANY_CACHE: Dict[int, Dict[str, str]] = {}
# 已知公司静态映射（接口拉取失败时兜底）
_KNOWN_COMPANIES = {
    5000000883: {"mdmCode": "9AHA", "name": "红河中石油昆仑燃气有限公司"},
    2: {"mdmCode": "9AH1", "name": "云南中石油昆仑燃气有限公司昆明分公司"},
}
# 账单记录时区（平台返回北京时间）
_CN_TZ = timezone(timedelta(hours=8))


class GasHttpClient:
    """昆仑燃气 HTTP 客户端"""

    def __init__(self, user_code: Optional[str] = None, cid: int = 2, terminal_type: int = 7):
        """
        初始化客户端

        Args:
            user_code: 燃气户号（8位数字），可选（用于扫码登录时不需要）
            cid: 地区代码（默认为2，昆明分公司）
            terminal_type: 终端类型（默认为7）
        """
        # Session 和 Token 管理
        self.user_code = user_code
        self.cid = cid
        self.terminal_type = terminal_type

        # Session 和 Token 管理
        self._session = requests.Session()
        self._token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._open_id: Optional[str] = None
        self._union_id: Optional[str] = None
        self._mdm_code: Optional[str] = None
        self._user_code_id: Optional[str] = None  # 缓存 userCodeId

        # 缓存 AES 密钥（用于密码登录）
        self._cached_aes_key: Optional[str] = None

        # 年度用量累计缓存（避免每次刷新都翻完整历史页）
        self._yearly_cache: Optional[Dict[str, Any]] = None
        # 公司名称（解析 mdmCode 时顺带缓存）
        self.company_name: Optional[str] = None

        # 设置默认请求头
        self._session.headers.update({
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.47(0x18002f2f) NetType/WIFI Language/zh_CN",
            "Content-Type": "application/json;charset=UTF-8",
        })

    def set_credentials(self, token: Optional[str] = None, refresh_token: Optional[str] = None,
                        union_id: Optional[str] = None, mdm_code: Optional[str] = None,
                        open_id: Optional[str] = None) -> None:
        """
        直接设置认证凭证（用于已保存的 token）

        Args:
            token: JWT 访问令牌
            refresh_token: JWT 刷新令牌（长期有效，约180天）
            union_id: 微信 UnionID
            mdm_code: 表计代码
            open_id: 微信 OpenID
        """
        if token:
            self._token = token
            _LOGGER.info(f"✅ Token set: {token[:20]}...")
        if refresh_token:
            self._refresh_token = refresh_token
            _LOGGER.info(f"✅ Refresh token set: {refresh_token[:20]}...")
        # close 接口实际使用 refreshToken 作为 token 请求头
        auth_token = self._refresh_token or self._token
        if auth_token:
            self._session.headers["token"] = auth_token
        if union_id:
            self._union_id = union_id
            _LOGGER.debug(f"UnionID set: {union_id[:20]}...")
        if mdm_code:
            self._mdm_code = mdm_code
            _LOGGER.info(f"✅ MDM code set: {mdm_code}")
        if open_id:
            self._open_id = open_id
            _LOGGER.debug(f"OpenID set: {open_id[:20]}...")

    def get_credentials(self) -> dict:
        """
        获取当前凭证（用于保存到配置）

        Returns:
            包含 token, refresh_token, union_id, mdm_code, open_id 的字典
        """
        return {
            "token": self._token,
            "refresh_token": self._refresh_token,
            "union_id": self._union_id,
            "mdm_code": self._mdm_code,
            "open_id": self._open_id,
        }

    def _get_auth_token(self) -> Optional[str]:
        """获取用于 close 接口的凭证。

        实测网上营业厅 close 接口需要把 refreshToken 放到 token 头才有效。
        """
        return self._refresh_token or self._token

    def _build_signed_headers(self, data: Optional[dict]) -> dict:
        """构造网上营业厅 close 接口签名头。

        规则：
        1. 请求体字段 + timestamp + token
        2. 按 key 字典序排序
        3. 拼接 key=value&... + API_SIGN_KEY
        4. MD5 得到 signature
        """
        auth_token = self._get_auth_token()
        if not auth_token:
            return {}
        ts = int(__import__('time').time() * 1000)
        entries = []
        body = data or {}
        for key, value in body.items():
            entries.append((key, value))
        entries.append(('timestamp', ts))
        entries.append(('token', auth_token))
        entries.sort(key=lambda item: str(item[0]))
        raw = '&'.join(f'{k}={v}' for k, v in entries) + API_SIGN_KEY
        signature = hashlib.md5(raw.encode('utf-8')).hexdigest()
        return {
            'token': auth_token,
            'timestamp': str(ts),
            'signature': signature,
            'X-Requested-With': 'XMLHttpRequest',
        }

    def _make_request(self, url: str, method: str = "POST", data: Optional[dict] = None,
                   requires_auth: bool = False, retry_after_refresh: bool = True) -> requests.Response:
        """发送HTTP请求（支持自动刷新Token和重试）"""
        full_url = f"{API_BASE}{url}"
        headers = dict(self._session.headers)

        # 如果需要认证且已有token，添加到请求头
        if requires_auth:
            auth_token = self._get_auth_token()
            if auth_token:
                headers.update(self._build_signed_headers(data))
                _LOGGER.debug(f"🔐 Using token for auth: {auth_token[:20]}...")
            else:
                _LOGGER.warning(f"⚠️  Auth required but no token available!")

        _LOGGER.debug(f"Request: {method} {full_url}")
        if data:
            _LOGGER.debug(f"  Data: {json.dumps(data, ensure_ascii=False)}")

        try:
            # 增加超时时间到 60 秒，避免慢速 API 导致超时
            response = self._session.post(full_url, json=data, headers=headers, timeout=60)

            # 检测 403 Forbidden (Token 过期)
            # 不再用 refreshToken 调 userAuthorization 刷新（该接口只收 code）
            # 交由上层用手机号+密码重新登录，成功后重试
            if response.status_code == 403 and requires_auth:
                _LOGGER.warning("⚠️  Got 403 Forbidden, upper layer will re-login if credentials exist...")

            response.raise_for_status()
            return response
        except requests.Timeout as err:
            _LOGGER.warning(f"Request timeout (60s): {err}")
            raise
        except requests.RequestException as err:
            _LOGGER.error(f"Request failed: {err}")
            if hasattr(err, 'response') and err.response is not None:
                _LOGGER.error(f"Response status: {err.response.status_code}")
                _LOGGER.error(f"Response body: {err.response.text[:500]}")
            raise
        except Exception as err:
            _LOGGER.error(f"Unexpected error: {err}")
            raise

    def _parse_response(self, response: requests.Response) -> dict:
        """解析API响应"""
        try:
            data = response.json()
            if data.get(FIELD_SUCCESS) or data.get(FIELD_SUCCESS_WITH_DATA):
                return data.get(FIELD_DATA, {})
            else:
                _LOGGER.warning(f"API returned error: {data.get(FIELD_MESSAGE, data)}")
                return {"error": data.get(FIELD_MESSAGE, "Unknown error")}
        except json.JSONDecodeError as err:
            _LOGGER.error(f"Failed to parse JSON response: {err}")
            return {"error": f"JSON decode error: {err}"}

    def login(self, wechat_code: str, union_id: str) -> bool:
        """
        使用微信授权码登录

        Args:
            wechat_code: 微信授权码
            union_id: 微信OpenID

        Returns:
            登录是否成功
        """
        url = API_USER_AUTH
        data = {
            PARAM_CID: DEFAULT_CID_NATIONWIDE,  # 使用固定值 "99999" 全国查询
            PARAM_CODE: wechat_code,
            PARAM_UNION_ID: union_id,
        }

        _LOGGER.info(f"Logging in with wechat code: {wechat_code[:10]}...")

        try:
            response = self._make_request(url, data=data, requires_auth=False)
            content = response.content.decode('utf-8')

            # 响应是 base64 编码的
            if content and not content.strip().startswith('{'):
                decoded_bytes = base64.b64decode(content)
                content = decoded_bytes.decode('utf-8')

            result = json.loads(content)

            if result.get(FIELD_SUCCESS) or result.get(FIELD_SUCCESS_WITH_DATA):
                data = result.get(FIELD_DATA, {})

                # 存储token和用户信息
                self._token = data.get("token")
                self._refresh_token = data.get("refreshToken")
                self._union_id = union_id  # 存储 union_id
                self._open_id = union_id  # 兼容性：也存储到 open_id
                self._mdm_code = data.get("mdmCode")

                _LOGGER.info(f"Login successful for user: {data.get('mobile', 'unknown')}")
                _LOGGER.debug(f"MDM code: {self._mdm_code}")

                # 更新session默认请求头，close 接口优先用 refreshToken
                auth_token = self._refresh_token or self._token
                if auth_token:
                    self._session.headers["token"] = auth_token

                return True
            else:
                _LOGGER.error(f"Login failed: {result.get(FIELD_MESSAGE, 'Unknown error')}")
                return False

        except Exception as err:
            _LOGGER.error(f"Login error: {err}")
            return False

    def is_logged_in(self) -> bool:
        """检查是否已登录（token 或 refresh_token 任一存在即可）"""
        return bool(self._token or self._refresh_token)

    def refresh_access_token(self) -> bool:
        """
        尝试刷新 access_token

        注意：API 可能没有专门的刷新端点。
        此方法尝试使用 userAuthorization 端点，但可能不支持 refreshToken 刷新。

        Returns:
            刷新是否成功
        """
        if not self._refresh_token:
            _LOGGER.error("❌ No refresh token available, cannot refresh access token")
            return False

        # 尝试使用 userAuthorization 端点（可能支持 refreshToken 参数）
        url = API_USER_AUTH  # /api/v1/open/wechat/userAuthorization
        data = {
            PARAM_CID: DEFAULT_CID_NATIONWIDE,
            "refreshToken": self._refresh_token,  # 尝试用 refreshToken 代替 code
            PARAM_UNION_ID: self._union_id or "",
        }

        _LOGGER.info("🔄 Attempting to refresh token via userAuthorization...")

        try:
            response = self._make_request(url, data=data, requires_auth=False)
            content = response.content.decode('utf-8')

            # 响应是 base64 编码
            if content and not content.strip().startswith('{'):
                decoded_bytes = base64.b64decode(content)
                content = decoded_bytes.decode('utf-8')

            result = json.loads(content)

            if result.get(FIELD_SUCCESS) or result.get(FIELD_SUCCESS_WITH_DATA):
                api_data = result.get(FIELD_DATA, {})
                new_token = api_data.get("token")
                new_refresh_token = api_data.get("refreshToken")

                if new_token:
                    self._token = new_token
                    self._session.headers["token"] = new_token
                    _LOGGER.info("✅ Access token refreshed successfully")

                    if new_refresh_token:
                        self._refresh_token = new_refresh_token
                        _LOGGER.info("✅ Refresh token also updated")

                    return True
            else:
                _LOGGER.warning(f"⚠️  Token refresh not supported: {result.get(FIELD_MESSAGE, 'API may not support refreshToken refresh')}")
                return False

        except Exception as err:
            _LOGGER.warning(f"⚠️  Token refresh failed: {err}")
            return False

    def _get_rsa_public_key(self) -> Optional[str]:
        """
        从服务器获取 RSA 公钥

        Returns:
            Base64 编码的 RSA 公钥，失败返回 None
        """
        url = API_GET_RSA_PUBLIC_KEY
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": "https://bol.grs.petrochina.com.cn",
            "Referer": "https://bol.grs.petrochina.com.cn/",
        }

        _LOGGER.info("🔑 Fetching RSA public key from server...")

        try:
            response = self._session.post(f"{API_BASE}{url}", json={}, headers=headers, timeout=30)
            response.raise_for_status()
            data = response.json()

            if data.get(FIELD_SUCCESS) or data.get(FIELD_SUCCESS_WITH_DATA):
                public_key = data.get(FIELD_DATA, {}).get("serverPublicKey")
                if public_key:
                    _LOGGER.info("✅ RSA public key received")
                    return public_key
                else:
                    _LOGGER.error("❌ serverPublicKey not found in response")
            else:
                _LOGGER.error(f"❌ Failed to get RSA key: {data.get(FIELD_MESSAGE)}")

        except Exception as err:
            _LOGGER.error(f"❌ Error fetching RSA public key: {err}")

        return None

    def _encrypt_with_rsa(self, plaintext: str, public_key_b64: str) -> Optional[str]:
        """
        使用 RSA 公钥加密数据

        Args:
            plaintext: 明文
            public_key_b64: Base64 编码的 RSA 公钥

        Returns:
            Base64 编码的密文，失败返回 None
        """
        try:
            # 添加 PEM 格式的头尾
            pem_key = f"-----BEGIN PUBLIC KEY-----\n{public_key_b64}\n-----END PUBLIC KEY-----"

            # 加载公钥
            public_key = serialization.load_pem_public_key(
                pem_key.encode(),
                backend=default_backend()
            )

            # RSA 加密（使用 PKCS1v15 padding，与 JSEncrypt 兼容）
            ciphertext = public_key.encrypt(
                plaintext.encode('utf-8'),
                padding.PKCS1v15()
            )

            # Base64 编码
            return base64.b64encode(ciphertext).decode('utf-8')

        except Exception as err:
            _LOGGER.error(f"❌ RSA encryption failed: {err}")
            return None

    def _encrypt_with_rsa_long(self, plaintext: str, public_key_b64: str) -> Optional[str]:
        """
        使用 RSA 公钥加密长数据（分块加密，类似 JSEncrypt 的 encryptLong）

        对于 RSA-1024：
        - 密文块大小：128 字节
        - 每块最大明文：117 字节（PKCS#1 v1.5 填充）

        Args:
            plaintext: 明文
            public_key_b64: Base64 编码的 RSA 公钥

        Returns:
            Base64 编码的密文，失败返回 None
        """
        try:
            # 添加 PEM 格式的头尾
            pem_key = f"-----BEGIN PUBLIC KEY-----\n{public_key_b64}\n-----END PUBLIC KEY-----"

            # 加载公钥
            public_key = serialization.load_pem_public_key(
                pem_key.encode(),
                backend=default_backend()
            )

            # 将明文转换为字节
            data = plaintext.encode('utf-8')

            # RSA-1024 每块最大明文大小（PKCS#1 v1.5）
            MAX_BLOCK_SIZE = 117

            # 分块加密
            encrypted_blocks = []
            for i in range(0, len(data), MAX_BLOCK_SIZE):
                chunk = data[i:i + MAX_BLOCK_SIZE]
                ciphertext = public_key.encrypt(
                    chunk,
                    padding.PKCS1v15()
                )
                encrypted_blocks.append(ciphertext)

            # 连接所有块并 Base64 编码
            combined = b''.join(encrypted_blocks)
            return base64.b64encode(combined).decode('utf-8')

        except Exception as err:
            _LOGGER.error(f"❌ RSA long encryption failed: {err}")
            return None

    def _get_aes_key(self) -> Optional[str]:
        """
        获取 AES 加密密钥（通过 RSA 密钥交换）

        Returns:
            Base64 编码的 AES 密钥（原始密钥，未加密），失败返回 None
        """
        try:
            # 步骤1: 生成客户端 RSA 密钥对
            _LOGGER.info("🔑 Generating client RSA key pair...")
            client_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=1024,
                backend=default_backend()
            )
            client_public_key = client_private_key.public_key()

            # 获取公钥的 DER 格式（RSAPublicKey，只包含 n 和 e）
            client_public_der = client_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.PKCS1
            )
            client_public_b64 = base64.b64encode(client_public_der).decode('utf-8')

            _LOGGER.debug(f"Client public key (DER PKCS1 b64, {len(client_public_b64)} chars): {client_public_b64[:50]}...")

            # 步骤2: 获取服务器 RSA 公钥
            server_public_key_b64 = self._get_rsa_public_key()
            if not server_public_key_b64:
                return None

            # 步骤3: 用服务器公钥加密客户端公钥
            _LOGGER.info("🔐 Encrypting client public key with server public key...")
            encrypted_client_public_key = self._encrypt_with_rsa_long(
                client_public_b64,
                server_public_key_b64
            )
            if not encrypted_client_public_key:
                return None

            # 步骤4: 调用 getKey API
            _LOGGER.info("📡 Calling getKey API...")
            url = f"{API_BASE}/api/v1/open/encrypt/getKey"
            headers = {
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "Origin": "https://bol.grs.petrochina.com.cn",
                "Referer": "https://bol.grs.petrochina.com.cn/",
            }

            response = self._session.post(
                url,
                json={"clientEncryptPublicKey": encrypted_client_public_key},
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            data = response.json()

            if not (data.get(FIELD_SUCCESS) or data.get(FIELD_SUCCESS_WITH_DATA)):
                _LOGGER.error(f"❌ getKey API failed: {data.get(FIELD_MESSAGE)}")
                return None

            encrypted_aes_key = data.get(FIELD_DATA, {}).get("key")
            if not encrypted_aes_key:
                _LOGGER.error("❌ No key in getKey response")
                return None

            # 步骤5: 用客户端私钥解密 AES 密钥
            _LOGGER.info("🔓 Decrypting AES key with client private key...")
            encrypted_aes_key_bytes = base64.b64decode(encrypted_aes_key)
            aes_key_bytes = client_private_key.decrypt(
                encrypted_aes_key_bytes,
                padding.PKCS1v15()
            )

            # 返回 Base64 编码的 AES 密钥
            aes_key_b64 = base64.b64encode(aes_key_bytes).decode('utf-8')
            _LOGGER.info(f"✅ AES key obtained ({len(aes_key_bytes)} bytes)")
            return aes_key_b64

        except Exception as err:
            _LOGGER.error(f"❌ Error getting AES key: {err}")
            import traceback
            _LOGGER.debug(traceback.format_exc())
            return None

    def _encrypt_with_aes(self, plaintext: str, aes_key_b64: str) -> Optional[str]:
        """
        使用 AES-128-ECB 加密数据（与网页版兼容）

        注意：网页版使用的是双重加密：
        1. 首先解密 aes_key_b64（使用 "1qaz2wsx"）
        2. 然后用解密后的密钥加密明文

        Args:
            plaintext: 明文
            aes_key_b64: Base64 编码的 AES 密钥（已被 "1qaz2wsx" 加密）

        Returns:
            Base64 编码的密文，失败返回 None
        """
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives.padding import PKCS7

            # 步骤1: 解密 AES 密钥（使用 "1qaz2wsx"）
            fixed_key = b"1qaz2wsx\x00\x00\x00\x00\x00\x00\x00\x00"  # 填充到16字节
            cipher = Cipher(algorithms.AES(fixed_key), modes.ECB(), backend=default_backend())
            decryptor = cipher.decryptor()

            encrypted_key_bytes = base64.b64decode(aes_key_b64)
            decrypted_key_padded = decryptor.update(encrypted_key_bytes) + decryptor.finalize()

            # 去除 PKCS7 填充
            unpadder = PKCS7(128).unpadder()
            actual_aes_key_bytes = unpadder.update(decrypted_key_padded) + unpadder.finalize()

            _LOGGER.debug(f"Decrypted AES key: {len(actual_aes_key_bytes)} bytes")

            # 步骤2: 使用解密后的密钥加密明文
            # PKCS7 填充
            padder = PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

            # AES-ECB 加密
            cipher = Cipher(algorithms.AES(actual_aes_key_bytes), modes.ECB(), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            # Base64 编码
            return base64.b64encode(ciphertext).decode('utf-8')

        except Exception as err:
            _LOGGER.error(f"❌ AES encryption failed: {err}")
            import traceback
            _LOGGER.debug(traceback.format_exc())
            return None


    def _encrypt_web_aes(self, plaintext: str) -> Optional[str]:
        """
        使用网页版固定 AES Key 加密（网上营业厅/公众号 H5 同款）。

        算法：AES-192-ECB / PKCS7
        Key：F9ce3yf0GPpbtal2YOE/Vg==（按 UTF-8 取 24 字节）
        """
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives.padding import PKCS7

            key = b"F9ce3yf0GPpbtal2YOE/Vg=="  # 24 bytes => AES-192
            padder = PKCS7(128).padder()
            padded = padder.update(plaintext.encode('utf-8')) + padder.finalize()
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(padded) + encryptor.finalize()
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as err:
            _LOGGER.error(f"❌ Web AES encryption failed: {err}")
            return None
    def password_login(self, mobile: str, password: str, company_id: Optional[int] = None, cached_aes_key: Optional[str] = None) -> bool:
        """
        使用手机号和密码登录（网上营业厅/公众号网页版）

        加密方式：固定 AES Key + AES-ECB/PKCS7
        Key：F9ce3yf0GPpbtal2YOE/Vg==（UTF-8 24字节）
        """
        _LOGGER.info(f"🔐 Attempting password login for: {mobile}")

        encrypted_mobile = self._encrypt_web_aes(mobile)
        encrypted_password = self._encrypt_web_aes(password)
        if not encrypted_mobile or not encrypted_password:
            _LOGGER.error("❌ Failed to encrypt credentials with web AES")
            return False

        _LOGGER.debug(f"Encrypted mobile: {encrypted_mobile[:20]}...")
        _LOGGER.debug(f"Encrypted password: {encrypted_password[:20]}...")

        url = API_PASSWORD_LOGIN
        data = {
            "mobile": encrypted_mobile,
            "password": encrypted_password,
        }
        if company_id:
            data["companyId"] = company_id

        try:
            response = self._make_request(url, data=data, requires_auth=False)
            content = response.content.decode('utf-8')

            # 兼容可能的 base64 包裹响应
            if content and not content.strip().startswith('{'):
                try:
                    decoded_bytes = base64.b64decode(content)
                    content = decoded_bytes.decode('utf-8')
                except Exception:
                    pass

            result = json.loads(content)

            if result.get(FIELD_SUCCESS) or result.get(FIELD_SUCCESS_WITH_DATA):
                api_data = result.get(FIELD_DATA, {})
                token = api_data.get("token")
                refresh_token = api_data.get("refreshToken")
                company_info = api_data.get("company")

                if refresh_token:
                    self._refresh_token = refresh_token
                if token:
                    self._token = token

                # 实测 close 接口需使用 refreshToken 作为 token 头
                auth_token = self._refresh_token or self._token
                if auth_token:
                    self._session.headers["token"] = auth_token

                # 尝试从返回信息中获取 mdmCode
                if company_info:
                    if isinstance(company_info, str):
                        try:
                            company_data = json.loads(company_info)
                            self._mdm_code = company_data.get("mdmCode")
                        except json.JSONDecodeError:
                            pass
                    elif isinstance(company_info, dict):
                        self._mdm_code = company_info.get("mdmCode")

                _LOGGER.info(f"✅ Password login successful for: {mobile}")
                return True
            else:
                _LOGGER.error(f"❌ Password login failed: {result.get(FIELD_MESSAGE, 'Unknown error')}")
                return False

        except Exception as err:
            _LOGGER.error(f"❌ Password login error: {err}")
            import traceback
            _LOGGER.debug(traceback.format_exc())
            return False

    def get_user_code_list(self) -> Optional[list]:
        """
        获取账户绑定的所有户号列表（需要登录）

        Returns:
            户号列表，每个元素包含户号、地址等信息
        """
        if not self.is_logged_in():
            _LOGGER.error("Not logged in. Please login first.")
            return None

        url = API_GET_CUSTOMER_INFO
        data = {
            PARAM_CID: self.cid,
            PARAM_TERMINAL_TYPE: self.terminal_type,
        }

        _LOGGER.info(f"Querying user code list: {self.cid}")
        response = self._make_request(url, data=data, requires_auth=True)
        result = self._parse_response(response)

        if isinstance(result, dict) and "error" in result:
            _LOGGER.error(f"Failed to get user code list: {result['error']}")
            return None

        if isinstance(result, list):
            return result
        return result.get("data", []) if isinstance(result, dict) else []

    def resolve_mdm_code(self, cid: int) -> Optional[str]:
        """根据 cid 解析 mdmCode（优先缓存/静态映射，其次拉取公司列表）"""
        if self._mdm_code:
            return self._mdm_code
        cached = _COMPANY_CACHE.get(cid) or _KNOWN_COMPANIES.get(cid)
        if cached:
            self.company_name = cached.get("name")
            return cached.get("mdmCode")
        try:
            response = self._make_request(API_GET_GAS_COMPANY_LIST, data={}, requires_auth=False)
            payload = response.json()
            for area in payload.get("data", []):
                if not isinstance(area, dict):
                    continue
                for group in (area.get("companyList") or {}).values():
                    if not isinstance(group, list):
                        continue
                    for comp in group:
                        if not isinstance(comp, dict):
                            continue
                        comp_id = comp.get("id")
                        if comp_id is None:
                            continue
                        entry = {"mdmCode": comp.get("mdmCode", ""), "name": comp.get("name", "")}
                        _COMPANY_CACHE[int(comp_id)] = entry
                        if int(comp_id) == int(cid):
                            self.company_name = entry["name"]
                            self._mdm_code = entry["mdmCode"]
            if self._mdm_code:
                return self._mdm_code
        except Exception as err:
            _LOGGER.warning(f"Failed to fetch company list: {err}")
        return None

    def get_user_message(self) -> Optional[dict]:
        """查询客户基本信息（营业厅模式，无需户号绑定）"""
        if not self.is_logged_in():
            _LOGGER.error("Not logged in. Please login first.")
            return None
        mdm_code = self.resolve_mdm_code(self.cid)
        if not mdm_code:
            _LOGGER.error("Cannot resolve mdmCode for cid=%s", self.cid)
            return None
        data = {"mdmCode": mdm_code, PARAM_USER_CODE: self.user_code}
        response = self._make_request(API_GET_USER_MESSAGE, data=data, requires_auth=True)
        result = self._parse_response(response)
        if "error" in result:
            _LOGGER.error(f"Failed to get user message: {result['error']}")
            return None
        return result

    def get_user_gas_volume(self, page_no: int = 1) -> Optional[dict]:
        """查询物联网表每日账单记录（营业厅模式，无需户号绑定）

        Returns:
            {"records": [{date, volume, cost, reading, last_reading, balance}...],
             "records_count": int}
            记录按时间倒序（最新在前），每页固定10条。
        """
        if not self.is_logged_in():
            _LOGGER.error("Not logged in. Please login first.")
            return None
        mdm_code = self.resolve_mdm_code(self.cid)
        if not mdm_code:
            _LOGGER.error("Cannot resolve mdmCode for cid=%s", self.cid)
            return None
        data = {"mdmCode": mdm_code, PARAM_USER_CODE: self.user_code, "pageNo": page_no}
        response = self._make_request(API_GET_USER_GAS_VOLUME, data=data, requires_auth=True)
        result = self._parse_response(response)
        if "error" in result:
            _LOGGER.error(f"Failed to get user gas volume: {result['error']}")
            return None
        records = []
        for item in result.get("userCodeList") or []:
            try:
                records.append({
                    "date": item.get("blDttm", ""),
                    "volume": float(item.get("billingVolume") or 0),
                    "cost": float(item.get("amount") or 0),
                    "reading": float(item.get("read") or 0),
                    "last_reading": float(item.get("lastRead") or 0),
                    "balance": float(item.get("balance") or 0),
                })
            except (TypeError, ValueError):
                continue
        try:
            records_count = int(result.get("recordsCount") or 0)
        except (TypeError, ValueError):
            records_count = 0
        return {"records": records, "records_count": records_count}

    def get_usage_summary(self) -> Optional[dict]:
        """基于每日账单记录汇总各周期用量/费用/阶梯单价。

        平台升级后 getMonthlyTotalGasVolume / smartMeterGasDaysRecords 对未绑定
        户号不可用，改用 getUserGasVolume（每页10条）翻页聚合：
        - 每次刷新固定翻7页（约70天），覆盖昨日/近31天/本月/上月；
        - 年度累计首次翻到年初为止，之后用缓存增量累加。
        """
        if not self.is_logged_in():
            return None

        base_pages = 7
        records: list = []
        records_count = 0
        for page in range(1, base_pages + 1):
            page_data = self.get_user_gas_volume(page)
            if not page_data:
                break
            records_count = page_data["records_count"]
            batch = page_data["records"]
            if not batch:
                break
            records.extend(batch)
            if len(records) >= records_count:
                break

        if not records:
            return None

        now = datetime.now(_CN_TZ)
        year_start = datetime(now.year, 1, 1, tzinfo=_CN_TZ)
        month_start = datetime(now.year, now.month, 1, tzinfo=_CN_TZ)
        if now.month == 1:
            last_month_start = datetime(now.year - 1, 12, 1, tzinfo=_CN_TZ)
        else:
            last_month_start = datetime(now.year, now.month - 1, 1, tzinfo=_CN_TZ)
        recent_start = now - timedelta(days=31)

        def parse_dt(s: str) -> Optional[datetime]:
            try:
                return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=_CN_TZ)
            except (ValueError, TypeError):
                return None

        last_day = records[0]
        recent_volume = recent_cost = 0.0
        cur_month_volume = cur_month_cost = 0.0
        last_month_volume = last_month_cost = 0.0
        for rec in records:
            dt = parse_dt(rec["date"])
            if dt is None:
                continue
            if dt >= recent_start:
                recent_volume += rec["volume"]
                recent_cost += rec["cost"]
            if dt >= month_start:
                cur_month_volume += rec["volume"]
                cur_month_cost += rec["cost"]
            elif dt >= last_month_start:
                last_month_volume += rec["volume"]
                last_month_cost += rec["cost"]

        # 年度累计：缓存命中则增量累加，否则继续翻页到年初
        yearly_volume = yearly_cost = 0.0
        scan_complete = True
        cache = self._yearly_cache
        if cache and cache.get("year") == now.year and cache.get("complete"):
            cutoff = parse_dt(cache.get("last_dt", ""))
            yearly_volume = cache.get("volume", 0.0)
            yearly_cost = cache.get("cost", 0.0)
            for rec in records:
                dt = parse_dt(rec["date"])
                if dt is None or (cutoff and dt <= cutoff):
                    continue
                if dt >= year_start:
                    yearly_volume += rec["volume"]
                    yearly_cost += rec["cost"]
        else:
            all_records = list(records)
            page = base_pages
            reached_year_start = any(
                (parse_dt(r["date"]) or now) < year_start for r in records
            )
            while not reached_year_start and len(all_records) < records_count and page < 80:
                page += 1
                page_data = self.get_user_gas_volume(page)
                if not page_data or not page_data["records"]:
                    break
                batch = page_data["records"]
                all_records.extend(batch)
                if any((parse_dt(r["date"]) or now) < year_start for r in batch):
                    reached_year_start = True
            for rec in all_records:
                dt = parse_dt(rec["date"])
                if dt and dt >= year_start:
                    yearly_volume += rec["volume"]
                    yearly_cost += rec["cost"]
            records = all_records
            scan_complete = reached_year_start or len(all_records) >= records_count

        self._yearly_cache = {
            "year": now.year,
            "volume": yearly_volume,
            "cost": yearly_cost,
            "last_dt": records[0]["date"],
            "complete": scan_complete,
        }

        # 当前有效单价（最新账单 金额/用量）；阶梯档位接口已不可用，返回0表示未知
        ladder_unit_price = 0.0
        for rec in records:
            if rec["volume"] > 0:
                ladder_unit_price = round(rec["cost"] / rec["volume"], 2)
                break

        return {
            "last_day_volume": last_day["volume"],
            "last_day_cost": round(last_day["cost"], 2),
            "last_day_date": last_day["date"],
            "meter_reading": last_day["reading"],
            "balance": last_day["balance"],
            "last_communication": last_day["date"],
            "recent_monthly_volume": round(recent_volume, 2),
            "recent_monthly_cost": round(recent_cost, 2),
            "current_month_volume": round(cur_month_volume, 2),
            "current_month_cost": round(cur_month_cost, 2),
            "monthly_volume": round(last_month_volume, 2),
            "monthly_cost": round(last_month_cost, 2),
            "yearly_volume": round(yearly_volume, 2),
            "yearly_cost": round(yearly_cost, 2),
            "ladder_stage": 0,
            "ladder_unit_price": ladder_unit_price,
        }

    def get_user_debt(self) -> Optional[GasAccount]:
        """
        查询用户余额

        2026-11 平台升级后 close/getUserDebt 改为需要绑定后的 userCodeId，
        且部分公司（如红河）收费系统迁移导致绑定/公开查询接口失效。
        优先走营业厅模式接口（getUserMessage + getUserGasVolume），
        已绑定账户走新版 getUserDebt，未登录时回退公开接口。

        Returns:
            GasAccount 对象，失败返回 None
        """
        if self._get_auth_token():
            # 1) 已绑定账户：getUserCode 拿 userCodeId，再调新版 getUserDebt
            try:
                list_data = {PARAM_CID: self.cid, PARAM_TERMINAL_TYPE: 1}
                response = self._make_request(API_GET_CUSTOMER_INFO, data=list_data, requires_auth=True)
                result = self._parse_response(response)
                if isinstance(result, list):
                    for item in result:
                        if str(item.get("userCode")) == str(self.user_code):
                            self._user_code_id = str(item.get("id", ""))
                            break
                if self._user_code_id:
                    debt_data = {PARAM_CID: self.cid, PARAM_USER_CODE_ID: self._user_code_id}
                    response = self._make_request(API_GET_USER_DEBT_AUTH, data=debt_data, requires_auth=True)
                    result = self._parse_response(response)
                    if "error" not in result and result:
                        return self._account_from_debt(result)
            except Exception as err:
                _LOGGER.debug(f"Bound-account getUserDebt failed, fallback to hall API: {err}")

            # 2) 营业厅模式：客户信息 + 最新账单（无需绑定）
            try:
                message = self.get_user_message()
                volume = self.get_user_gas_volume(1)
                latest = (volume or {}).get("records", [{}])[0] if volume and volume["records"] else {}
                if message or latest:
                    message = message or {}
                    balance = latest.get("balance")
                    if balance is None:
                        balance = message.get("balance", 0)
                    mdm_code = self._mdm_code or self.resolve_mdm_code(self.cid) or ""
                    return GasAccount(
                        account_id="",
                        user_code=self.user_code,
                        customer_name=message.get("customerName", ""),
                        address=message.get("address", ""),
                        remote_meter_balance=float(balance or 0),
                        meter_type=message.get("modelType", ""),
                        mdm_code=mdm_code,
                        reading_last_time=str(latest.get("reading", message.get("lastBaseVolume", ""))),
                        remote_meter_last_communication_time=latest.get("date", ""),
                        user_code_id=self._user_code_id,
                    )
            except Exception as err:
                _LOGGER.error(f"Hall API get_user_debt failed: {err}")
            return None

        # 3) 未登录：公开接口（部分公司仍可用）
        data = {
            PARAM_CID: self.cid,
            PARAM_USER_CODE: self.user_code,
            PARAM_TERMINAL_TYPE: self.terminal_type,
        }
        _LOGGER.info(f"Querying user debt (public API): {self.user_code}")
        response = self._make_request(API_GET_USER_DEBT, data=data, requires_auth=False)
        result = self._parse_response(response)
        if "error" in result:
            _LOGGER.error(f"Failed to get user debt: {result['error']}")
            return None
        return self._account_from_debt(result)

    def _account_from_debt(self, account_data: dict) -> GasAccount:
        """从 getUserDebt 响应构造 GasAccount"""
        user_code_id = None
        user_code_list = account_data.get("userCodeList", [])
        if user_code_list and len(user_code_list) > 0:
            user_code_id = str(user_code_list[0].get("id", ""))
            self._user_code_id = user_code_id
        return GasAccount(
            account_id=account_data.get(DATA_ACCOUNT_ID, ""),
            user_code=account_data.get(PARAM_USER_CODE, self.user_code),
            customer_name=account_data.get(DATA_CUSTOMER_NAME, ""),
            address=account_data.get(DATA_ADDRESS, ""),
            remote_meter_balance=float(account_data.get(DATA_REMOTE_METER_BALANCE, 0)),
            meter_type=account_data.get(DATA_METER_TYPE, ""),
            mdm_code=account_data.get(DATA_MDM_CODE, ""),
            reading_last_time=account_data.get(DATA_READING_LAST_TIME, ""),
            remote_meter_last_communication_time=account_data.get(DATA_REMOTE_METER_LAST_COMMUNICATION_TIME, ""),
            user_code_id=user_code_id,
        )

    def get_customer_info(self) -> Optional[GasAccount]:
        """
        查询客户详细信息（需要认证）

        Returns:
            GasAccount 对象
        """
        if not self.is_logged_in():
            _LOGGER.error("Not logged in. Please login first.")
            return None

        url = API_GET_CUSTOMER_INFO
        data = {
            PARAM_CID: self.cid,
            PARAM_USER_CODE: self.user_code,
            PARAM_TERMINAL_TYPE: self.terminal_type,
            PARAM_USER_CODE_ID: "",
        }

        _LOGGER.info(f"Querying customer info: {self.user_code}")
        response = self._make_request(url, data=data, requires_auth=True)
        result = self._parse_response(response)

        if "error" in result:
            _LOGGER.error(f"Failed to get customer info: {result['error']}")
            return None

        # get_user_debt 和 get_customer_info 返回的数据结构可能相同
        return self.get_user_debt()

    def get_meter_reading(self, days: int = 30) -> Optional[list]:
        """
        查询表计读数（需要认证）

        Args:
            days: 查询天数（默认30天）

        Returns:
            表计读数列表，每个元素包含日期、读数、用量等
        """
        if not self.is_logged_in():
            _LOGGER.error("Not logged in. Please login first.")
            return None

        # 使用新的URL格式: /api/v1/close/recharge/smartMeterGasDaysRecords/{mdmCode}/{userCode}
        mdm_code = self._mdm_code or "9AH1"
        url = f"/api/v1/close/recharge/smartMeterGasDaysRecords/{mdm_code}/{self.user_code}"
        data = {}

        _LOGGER.info(f"Querying meter reading ({days} days): {self.user_code}")
        response = self._make_request(url, data=data, requires_auth=True)
        result = self._parse_response(response)

        if "error" in result:
            _LOGGER.error(f"Failed to get meter reading: {result['error']}")
            return None

        # 解析返回数据
        # 注意：API 返回的字段是 recordsInfo，不是 smartMeterGasDaysRecords
        account_data = result
        if account_data:
            return [{
                "date": record.get("gasYear", "")[:10],  # gasYear 实际是日期
                "reading": float(record.get("gasFee", 0)),  # gasFee 实际是表读数
                "volume": float(record.get("gasVolume", 0)),
                "cost": 0,  # API 没有返回费用
            } for record in account_data.get("recordsInfo", [])]
        return []

    def get_daily_usage(self, days: int = 30) -> Optional[dict]:
        """
        查询每日用气量统计（需要认证）

        Args:
            days: 查询天数（默认30天）

        Returns:
            包含每日用气量统计的字典
        """
        if not self.is_logged_in():
            _LOGGER.error("Not logged in. Please login first.")
            return None

        mdm_code = self._mdm_code or "9AH1"
        url = f"/api/v1/close/recharge/smartMeterGasDaysRecords/{mdm_code}/{self.user_code}"
        data = {}

        _LOGGER.info(f"Querying daily usage ({days} days): {self.user_code}")
        response = self._make_request(url, data=data, requires_auth=True)

        # 调试：记录响应状态码
        _LOGGER.debug(f"Daily usage response status: {response.status_code}")

        result = self._parse_response(response)

        # 调试：记录返回的原始数据
        _LOGGER.debug(f"Daily usage API response keys: {list(result.keys()) if result else 'None'}")
        _LOGGER.debug(f"recordsInfo found: {'recordsInfo' in result if result else 'N/A'}")
        if result and "recordsInfo" in result:
            records_count = len(result.get("recordsInfo", []))
            _LOGGER.debug(f"Records count: {records_count}")
            if records_count > 0:
                _LOGGER.debug(f"First record: {result.get('recordsInfo', [])[0]}")

        if "error" in result:
            _LOGGER.error(f"Failed to get daily usage: {result['error']}")
            return None

        # 解析返回数据并汇总
        # 注意：API 返回的字段是 recordsInfo，不是 smartMeterGasDaysRecords
        daily_volumes = []
        if result:
            records = result.get("recordsInfo", [])
            for record in records:
                daily_volumes.append({
                    "date": record.get("gasYear", "")[:10],  # gasYear 实际是日期 "2026/02/14"
                    "volume": float(record.get("gasVolume", 0)),
                    "cost": float(record.get("gasFee", 0)),  # gasFee 实际是表读数
                    "reading": float(record.get("gasFee", 0)),  # 保存表读数
                })

        return {
            "daily_volumes": daily_volumes,
            "total_volume": sum(d["volume"] for d in daily_volumes),
            "total_cost": sum(d["cost"] for d in daily_volumes),
        }

    def get_payment_records(self, page: int = 1, page_size: int = 10, user_code_id: str = "") -> Optional[dict]:
        """
        查询缴费记录（需要认证）

        优先走营业厅接口 getPaymentRecordListForHall（无需户号绑定），
        失败时回退到需要 userCodeId 的 getPaymentRecordList。

        Args:
            page: 页码（默认1）
            page_size: 每页数量（默认10）
            user_code_id: 用户代码ID（可选，如果不提供则使用缓存的值）

        Returns:
            缴费记录列表
        """
        if not self.is_logged_in():
            _LOGGER.error("Not logged in. Please login first.")
            return None

        _LOGGER.info(f"Querying payment records: {self.user_code}")

        mdm_code = self._mdm_code or self.resolve_mdm_code(self.cid)
        if mdm_code:
            hall_data = {
                PARAM_CID: self.cid,
                "mdmCode": mdm_code,
                PARAM_USER_CODE: self.user_code,
                PARAM_PAGE_NUMBER: page,
                PARAM_PAGE_SIZE: page_size,
            }
            try:
                response = self._make_request(API_GET_PAYMENT_RECORDS_HALL, data=hall_data, requires_auth=True)
                result = self._parse_response(response)
                if "error" not in result:
                    for record in result.get("recordsInfoList") or []:
                        op_date = record.get("operationDate") or ""
                        op_time = record.get("operationTime") or ""
                        if op_date and op_time:
                            record["operationDate"] = f"{op_date} {op_time}"
                    return result
                _LOGGER.warning(f"Payment records (hall) error: {result['error']}")
            except Exception as err:
                _LOGGER.warning(f"Payment records (hall) failed, fallback: {err}")

        url = API_GET_PAYMENT_RECORDS
        data = {
            PARAM_CID: self.cid,
            PARAM_PAGE_NUMBER: page,
            PARAM_PAGE_SIZE: page_size,
        }

        # 使用传入的 user_code_id 或缓存的值
        code_id = user_code_id or self._user_code_id
        if code_id:
            data[PARAM_USER_CODE_ID] = code_id
        else:
            _LOGGER.warning("userCodeId not available, payment records may fail")

        response = self._make_request(url, data=data, requires_auth=True)
        result = self._parse_response(response)

        if "error" in result:
            _LOGGER.error(f"Failed to get payment records: {result['error']}")
            return None

        return result

    def get_monthly_usage(self, page: int = 1, page_size: int = 7, length_time_yqqs: str = "2") -> Optional[dict]:
        """
        查询月度用气量统计（需要认证）

        Args:
            page: 页码（默认1）
            page_size: 每页数量（默认7）
            length_time_yqqs: 查询时长（默认"2"）

        Returns:
            月度用气量和阶梯价格信息
        """
        if not self.is_logged_in():
            _LOGGER.error("Not logged in. Please login first.")
            return None

        url = API_GET_MONTHLY_VOLUME
        data = {
            PARAM_CID: self.cid,
            PARAM_USER_CODE: self.user_code,
            PARAM_PAGE: page,
            PARAM_PAGE_SIZE: page_size,
            PARAM_LENGTH_TIME_YQQS: length_time_yqqs,
        }

        _LOGGER.info(f"Querying monthly usage: {self.user_code}")
        response = self._make_request(url, data=data, requires_auth=True)

        # 解析 base64 响应
        try:
            content = response.content.decode('utf-8')
            # 检查是否是 base64 编码
            if content and not content.strip().startswith('{'):
                decoded_bytes = base64.b64decode(content)
                content = decoded_bytes.decode('utf-8')
                result = json.loads(content)
            else:
                result = json.loads(content)

            if result.get(FIELD_SUCCESS) or result.get(FIELD_SUCCESS_WITH_DATA):
                return result.get(FIELD_DATA, {})
            else:
                _LOGGER.warning(f"API returned error: {result.get(FIELD_MESSAGE, result)}")
                return {"error": result.get(FIELD_MESSAGE, "Unknown error")}
        except Exception as err:
            _LOGGER.error(f"Failed to parse monthly usage response: {err}")
            return {"error": f"Parse error: {err}"}

    def get_ladder_pricing(self) -> Optional[dict]:
        """
        查询阶梯价格信息（通过月度用量接口获取）

        Returns:
            阶梯价格配置字典，包含各档位价格
        """
        monthly_data = self.get_monthly_usage(page=1, page_size=1)

        if monthly_data and "error" not in monthly_data:
            rate_items = monthly_data.get(DATA_RATE_ITEM_INFO, [])

            # 解析阶梯价格
            result = {
                "current_ladder": 1,  # 需要根据累计用量计算
                "ladder_1": {},
                "ladder_2": {},
                "ladder_3": {},
            }

            for item in rate_items:
                rate_name = item.get("rateName", "")
                if "第一" in rate_name or "1" in rate_name:
                    result["ladder_1"] = {
                        "price": float(item.get("price", 0)),
                        "start": float(item.get("beginVolume", 0)),
                        "end": float(item.get("endVolume", 0)),
                    }
                elif "第二" in rate_name or "2" in rate_name:
                    result["ladder_2"] = {
                        "price": float(item.get("price", 0)),
                        "start": float(item.get("beginVolume", 0)),
                        "end": float(item.get("endVolume", 0)),
                    }
                elif "第三" in rate_name or "3" in rate_name:
                    result["ladder_3"] = {
                        "price": float(item.get("price", 0)),
                        "start": float(item.get("beginVolume", 0)),
                        "end": float(item.get("endVolume", 0)),
                    }

            return result

        return None

    def create_login_qr_code(self) -> tuple[str, str]:
        """
        生成登录二维码

        Returns:
            (login_id, image_link): login_id用于后续查询状态，image_link是二维码图片URL
        """
        import time

        # Just pass the endpoint path, _make_request will add API_BASE
        url = API_CREATE_QR_CODE

        payload = {
            PARAM_CID: self.cid,
            PARAM_TERMINAL_TYPE: self.terminal_type,
            PARAM_TIMESTAMP: int(time.time() * 1000),
        }

        try:
            response = self._make_request(url, data=payload, requires_auth=False)
            data = response.json()

            if data.get(FIELD_SUCCESS) or data.get(FIELD_SUCCESS_WITH_DATA):
                login_id = data.get(FIELD_DATA, {}).get("loginId", "")
                image_url = data.get(FIELD_DATA, {}).get("qrCodeUrl", "")
                _LOGGER.info(f"QR code created: login_id={login_id}")
                return login_id, image_url
            else:
                from . import CSGAPIError
                raise CSGAPIError(data.get(FIELD_MESSAGE, "生成二维码失败"))
        except Exception as err:
            _LOGGER.error(f"Failed to create QR code: {err}")
            raise

    def check_qr_login_status(self, login_id: str) -> Tuple[bool, Optional[str]]:
        """
        查询二维码扫描状态

        Args:
            login_id: 二维码登录ID

        Returns:
            (success, auth_token): success是否成功，auth_token是登录后的token
        """
        # Just pass the endpoint path, _make_request will add API_BASE
        url = API_CHECK_QR_STATUS

        payload = {
            PARAM_LOGIN_ID: login_id,
            PARAM_CID: self.cid,
        }

        try:
            response = self._make_request(url, data=payload, requires_auth=False)
            data = response.json()

            logged_in = data.get("logged_in", False)
            if logged_in:
                # 用户已扫码登录，获取token
                token = data.get(FIELD_DATA, {}).get("token", "")
                union_id = data.get(FIELD_DATA, {}).get("unionId", "")
                mdm_code = data.get(FIELD_DATA, {}).get("mdmCode", "")
                refresh_token = data.get(FIELD_DATA, {}).get("refreshToken", "")

                # 更新session
                self._token = token
                self._refresh_token = refresh_token
                self._union_id = union_id  # 存储 union_id
                self._open_id = union_id  # 兼容性：也存储到 open_id
                self._mdm_code = mdm_code

                # 更新session请求头
                auth_token = self._refresh_token or self._token
                if auth_token:
                    self._session.headers["token"] = auth_token

                _LOGGER.info(f"QR login successful, token received")
                if refresh_token:
                    _LOGGER.info("✅ Refresh token also received from QR login")
                return True, token
            else:
                return False, None
        except Exception as err:
            _LOGGER.error(f"Failed to check QR status: {err}")
            raise

    def close(self):
        """关闭客户端会话"""
        self._session.close()
        _LOGGER.debug("HTTP client session closed")
