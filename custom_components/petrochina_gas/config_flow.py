# -*- coding: utf-8 -*-
"""Config flow for PetroChina Gas integration."""

import copy
import logging
import time
import requests
from typing import Any, Optional

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResult
from requests import RequestException

from .const import (
    CONF_ACCOUNTS,
    CONF_CID,
    CONF_GENERAL_ERROR,
    CONF_SETTINGS,
    CONF_TERMINAL_TYPE,
    CONF_TOKEN,
    CONF_REFRESH_TOKEN,
    CONF_MDM_CODE,
    CONF_OPEN_ID,
    CONF_UNION_ID,
    CONF_MOBILE,
    CONF_PASSWORD,
    CONF_COMPANY_ID,
    CONF_UPDATE_INTERVAL,
    CONF_UPDATED_AT,
    CONF_USER_CODE,
    DEFAULT_UPDATE_INTERVAL,
    DOMAIN,
    ERROR_CANNOT_CONNECT,
    ERROR_INVALID_AUTH,
    ERROR_UNKNOWN,
    STEP_ADD_ACCOUNT_DIRECT,
    STEP_INIT,
    STEP_SETTINGS,
    STEP_USER,
)
from .gas_client import (
    GasHttpClient,
    CSGAPIError,
)

_LOGGER = logging.getLogger(__name__)

# 静态备用公司列表（动态拉取失败时使用）
FALLBACK_COMPANY_OPTIONS = [
    "5000000883 - 云南红河：红河中石油昆仑燃气有限公司（9AHA）",
    "2 - 云南昆明：云南中石油昆仑燃气有限公司昆明分公司（9AH1）",
    "5000000020 - 测试：平安国际燃气（ZZ11）",
]

GAS_COMPANY_API = "https://bol.grs.petrochina.com.cn/api/v1/open/home/getGasCompanyList"


class PetrochinaGasConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for PetroChina Gas Statistics."""

    VERSION = 1
    _reauth_entry: Optional[config_entries.ConfigEntry] = None

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Create the options flow."""
        return PetrochinaGasOptionsFlowHandler(config_entry)

    def _fetch_company_options(self) -> list[str]:
        """从接口拉取燃气公司列表，失败时返回备用列表。"""
        try:
            resp = requests.post(
                GAS_COMPANY_API,
                json={},
                headers={
                    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.47(0x18002f2f) NetType/WIFI Language/zh_CN",
                    "Accept": "application/json, text/plain, */*",
                    "Origin": "https://bol.grs.petrochina.com.cn",
                    "Referer": "https://bol.grs.petrochina.com.cn/",
                },
                timeout=15,
            )
            resp.raise_for_status()
            payload = resp.json()
            options = []
            for area in payload.get("data", []):
                area_name = ""
                if isinstance(area, dict) and isinstance(area.get("area"), dict):
                    area_name = area["area"].get("name", "") or ""
                company_groups = area.get("companyList", {}) if isinstance(area, dict) else {}
                if not isinstance(company_groups, dict):
                    continue
                for group in company_groups.values():
                    if not isinstance(group, list):
                        continue
                    for comp in group:
                        if not isinstance(comp, dict):
                            continue
                        cid = comp.get("id")
                        name = comp.get("name", "")
                        mdm = comp.get("mdmCode", "")
                        if cid and name:
                            options.append(f"{cid} - {area_name}：{name}（{mdm}）")
            if options:
                # 云南红河排前面，方便选择
                honghe = [o for o in options if "9AHA" in o or "5000000883" in o]
                rest = [o for o in options if o not in honghe]
                return honghe + sorted(rest)
        except Exception as err:
            _LOGGER.warning("Failed to fetch company list, use fallback: %s", err)
        return list(FALLBACK_COMPANY_OPTIONS)

    @staticmethod
    def _parse_company_option(option: str) -> Optional[int]:
        """从公司选项字符串中解析 cid。"""
        try:
            return int(str(option).split(" - ", 1)[0].strip())
        except (ValueError, TypeError, IndexError):
            return None

    async def async_step_user(
        self, user_input: Optional[dict[str, Any]] = None
    ) -> FlowResult:
        """Handle the initial step - show account form directly."""
        DEFAULT_TERMINAL_TYPE = 7

        if user_input is None:
            # 拉取燃气公司列表，做成下拉选择
            company_options = await self.hass.async_add_executor_job(
                self._fetch_company_options
            )
            # 默认选中云南红河（如果存在）
            default_company = company_options[0] if company_options else FALLBACK_COMPANY_OPTIONS[0]
            for option in company_options:
                if "红河" in option or "9AHA" in option:
                    default_company = option
                    break

            schema = vol.Schema({
                vol.Required(CONF_USER_CODE): vol.All(
                    str, vol.Length(min=1), msg="请输入燃气户号"
                ),
                vol.Required(CONF_COMPANY_ID, default=default_company): vol.In(company_options),
                vol.Optional(CONF_MOBILE): str,
                vol.Optional(CONF_PASSWORD): str,
            })
            return self.async_show_form(
                step_id=STEP_USER,
                data_schema=schema,
                description_placeholders={
                    "description": "<p>请输入您的燃气户号和登录凭证。</p>"
                    "<p>燃气户号支持 8~20 位，实际以燃气公司户号为准。</p>"
                    "<p>请选择您所属的省/燃气公司。</p>"
                    "<p>手机号和密码为选填，填写后可自动登录获取详细数据。</p>"
                },
            )

        user_code = str(user_input.get(CONF_USER_CODE, "")).strip()
        company_option = str(user_input.get(CONF_COMPANY_ID, "")).strip()
        cid = self._parse_company_option(company_option)
        if cid is None:
            # 兼容老配置直接填数字 cid
            cid = user_input.get(CONF_CID, 2)
        terminal_type = DEFAULT_TERMINAL_TYPE

        auth_settings = {}
        if user_input.get(CONF_MOBILE):
            auth_settings[CONF_MOBILE] = user_input[CONF_MOBILE]
        if user_input.get(CONF_PASSWORD):
            auth_settings[CONF_PASSWORD] = user_input[CONF_PASSWORD]

        await self.async_set_unique_id(f"GAS-{user_code}")

        return await self._create_or_update_config_entry(
            user_code, cid, terminal_type, auth_settings
        )

    async def _create_or_update_config_entry(
        self, user_code, cid, terminal_type, settings: Optional[dict] = None
    ) -> FlowResult:
        """Create or update config entry"""
        # 获取现有配置（如果有）
        if self._reauth_entry:
            old_config = copy.deepcopy(self._reauth_entry.data)
            existing_accounts = old_config.get(CONF_ACCOUNTS, {})
            existing_settings = old_config.get(CONF_SETTINGS, {})
        else:
            existing_accounts = {}
            existing_settings = {}

        # 构建账户配置，包含认证信息
        account_config = {
            CONF_USER_CODE: user_code,
            CONF_CID: cid,
            CONF_TERMINAL_TYPE: terminal_type,
        }

        # 如果提供了认证信息，添加到账户级别
        if settings:
            for key in [CONF_MOBILE, CONF_PASSWORD]:
                if settings.get(key):
                    account_config[key] = settings[key]

        data = {
            CONF_USER_CODE: user_code,
            CONF_CID: cid,
            CONF_TERMINAL_TYPE: terminal_type,
            CONF_ACCOUNTS: {
                **existing_accounts,
                user_code: account_config,
            },
            CONF_SETTINGS: {
                CONF_UPDATE_INTERVAL: existing_settings.get(CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL),
            },
            CONF_UPDATED_AT: str(int(time.time() * 1000)),
        }

        # Add auth settings if provided (to global settings for backward compatibility)
        if settings:
            data[CONF_SETTINGS].update(settings)

        # handle normal creation and reauth
        if self._reauth_entry:
            # reauth
            old_config = copy.deepcopy(self._reauth_entry.data)
            data[CONF_ACCOUNTS] = old_config.get(CONF_ACCOUNTS, {})
            data[CONF_SETTINGS] = old_config.get(CONF_SETTINGS, {})
            self.hass.config_entries.async_update_entry(self._reauth_entry, data=data)
            await self.hass.config_entries.async_reload(self._reauth_entry.entry_id)
            self._reauth_entry = None
            return self.async_abort(reason="reauth_successful")

        return self.async_create_entry(
            title=f"PetroChina Gas {user_code}",
            data=data,
        )

    async def async_step_reauth(self, user_input=None):
        """Perform reauth upon an API authentication error."""
        self._reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        return await self.async_step_user()


class PetrochinaGasOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options flow for PetroChina Gas Statistics."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(
        self, user_input: Optional[dict[str, Any]] = None
    ) -> FlowResult:
        """Manage options - show menu."""
        # 兼容旧版 HA：使用表单代替 async_show_menu
        if user_input is not None:
            action = user_input.get("action")
            if action == "settings":
                return await self.async_step_settings()
            elif action == "auth":
                return await self.async_step_auth()

        schema = vol.Schema({
            vol.Required("action"): vol.In({
                "settings": "更新间隔设置",
                "auth": "认证信息设置",
            }),
        })

        return self.async_show_form(
            step_id=STEP_INIT,
            data_schema=schema,
            description_placeholders={
                "description": "<p>请选择要修改的设置项</p>"
            }
        )

    async def async_step_settings(
        self, user_input: Optional[dict[str, Any]] = None
    ) -> FlowResult:
        """Manage update interval settings."""
        settings = self.config_entry.data.get(CONF_SETTINGS, {})
        current_interval = settings.get(CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL)

        schema = vol.Schema({
            vol.Required(CONF_UPDATE_INTERVAL, default=current_interval): vol.All(
                int, vol.Range(min=60), msg="刷新间隔不能低于60秒"
            ),
        })

        if user_input:
            # 使用 dict() 转换，避免 MappingProxyType 不可变问题
            new_data = dict(self.config_entry.data)
            new_settings = dict(new_data.get(CONF_SETTINGS, {}))
            new_settings[CONF_UPDATE_INTERVAL] = user_input[CONF_UPDATE_INTERVAL]
            new_data[CONF_SETTINGS] = new_settings
            new_data[CONF_UPDATED_AT] = str(int(time.time() * 1000))
            self.hass.config_entries.async_update_entry(
                self.config_entry,
                data=new_data,
            )
            return self.async_create_entry(title="", data=user_input)

        return self.async_show_form(step_id=STEP_SETTINGS, data_schema=schema)

    async def async_step_auth(
        self, user_input: Optional[dict[str, Any]] = None
    ) -> FlowResult:
        """Manage authentication credentials."""
        settings = self.config_entry.data.get(CONF_SETTINGS, {})

        # 获取当前账户信息
        accounts = self.config_entry.data.get(CONF_ACCOUNTS, {})
        if not accounts:
            return self.async_abort(reason="no_account")

        # 获取第一个账户的认证信息作为默认值
        first_account = list(accounts.values())[0]
        defaults = {
            CONF_MOBILE: settings.get(CONF_MOBILE) or first_account.get(CONF_MOBILE, ""),
            CONF_PASSWORD: settings.get(CONF_PASSWORD) or first_account.get(CONF_PASSWORD, ""),
        }

        if user_input is None:
            schema = vol.Schema({
                vol.Optional(CONF_MOBILE, default=defaults[CONF_MOBILE]): str,
                vol.Optional(CONF_PASSWORD, default=defaults[CONF_PASSWORD]): str,
            })
            return self.async_show_form(
                step_id="auth",
                data_schema=schema,
                description_placeholders={
                    "description": "<p>更新登录凭证。</p>"
                    "<p>系统将使用手机号和密码自动登录，Token过期时会自动重新获取。</p>"
                    "<p>留空保持不变。</p>"
                }
            )

        # 保存认证信息
        new_data = copy.deepcopy(dict(self.config_entry.data))
        new_settings = dict(new_data.get(CONF_SETTINGS, {}))

        # 更新全局设置
        for key in [CONF_MOBILE, CONF_PASSWORD]:
            if user_input.get(key):  # 只更新非空值
                new_settings[key] = user_input[key]

        new_data[CONF_SETTINGS] = new_settings
        new_data[CONF_UPDATED_AT] = str(int(time.time() * 1000))

        # 同时更新所有账户的认证信息
        for account_key, account_config in new_data.get(CONF_ACCOUNTS, {}).items():
            for key in [CONF_MOBILE, CONF_PASSWORD]:
                if user_input.get(key):
                    account_config[key] = user_input[key]

        self.hass.config_entries.async_update_entry(
            self.config_entry,
            data=new_data,
        )

        return self.async_create_entry(title="", data=user_input)
