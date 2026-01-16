import sys
import time
import logging
import getpass
import json
from dataclasses import dataclass
from typing import Dict, Any, Optional
from selenium import webdriver
from selenium.webdriver.chrome.webdriver import WebDriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class AppConfig:
    LOGIN_URL: str
    USERNAME: str
    PASSWORD: str
    TENANT_VALUE: str
    TENANT_IDENTIFIER: str = "tenantid"
    TIMEOUT: int = 30
    HEADLESS: bool = False
    PROXY: Optional[str] = None  # REQUIRED for ZAP

class KendoUtils:
    """ YOUR KENDO LOGIC - KEPT EXACTLY AS IS """
    def __init__(self, driver: WebDriver, timeout: int):
        self.driver = driver
        self.wait = WebDriverWait(driver, timeout)

    def safe_click(self, element: WebElement):
        try:
            self.wait.until(EC.element_to_be_clickable(element))
            element.click()
        except Exception:
            logger.info("Standard click failed, attempting JS click.")
            self.driver.execute_script("arguments[0].click();", element)

    def kendo_search_and_select(self, identifier: str, value: str):
        try:
            xpath_locator = (
                f"//kendo-combobox["
                f"@id='{identifier}' or "
                f"@data-cy='{identifier}'"
                f"]"
            )
            logger.info(f"Looking for Kendo Combobox: '{identifier}'")
            wrapper = self.wait.until(
                EC.visibility_of_element_located((By.XPATH, xpath_locator))
            )
            try:
                arrow_btn = wrapper.find_element(By.CSS_SELECTOR, ".k-input-button")
                self.safe_click(arrow_btn)
                time.sleep(0.5)
            except Exception:
                pass
 
            input_element = wrapper.find_element(By.TAG_NAME, "input")
            input_element.clear()
            for char in value:
                input_element.send_keys(char)
                time.sleep(0.05)
 
            item_xpath = "//*[@role='gridcell' or @role='option']"
            self.wait.until(EC.presence_of_element_located((By.XPATH, item_xpath)))
            suggestions = self.driver.find_elements(By.XPATH, item_xpath)
 
            match_found = False
            for item in suggestions:
                if item.text.strip() == value:
                    self.safe_click(item)
                    match_found = True
                    break
 
            if not match_found:
                input_element.send_keys(Keys.ENTER)
        except Exception as e:
            logger.error(f"Kendo interaction failed for '{identifier}': {e}")
            raise

class DefenderAutomation:
    def __init__(self, config: AppConfig):
        self.config = config
        self.driver = self._init_driver()
        self.wait = WebDriverWait(self.driver, self.config.TIMEOUT)
        self.kendo = KendoUtils(self.driver, self.config.TIMEOUT)

    def _init_driver(self) -> WebDriver:
        options = Options()
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--allow-insecure-localhost") # Added for ZAP stability
        options.add_argument("--start-maximized")
        options.page_load_strategy = "eager"
        
        if self.config.HEADLESS:
            options.add_argument("--headless=new")

        # --- REQUIRED: PROXY CONFIG FOR ZAP ---
        if self.config.PROXY:
            clean_proxy = self.config.PROXY.replace("http://", "").replace("https://", "")
            logger.info(f"Setting Proxy: {clean_proxy}")
            options.add_argument(f"--proxy-server={clean_proxy}")

        return webdriver.Chrome(options=options)
 
    def bypass_ssl_warning(self):
        try:
            time.sleep(2)
            if "not private" in self.driver.page_source.lower():
                self.driver.find_element(By.TAG_NAME, "body").send_keys("thisisunsafe")
        except Exception:
            pass

    def fill_credentials(self):
        """ YOUR TESTED LOGIC """
        logger.info("Filling credentials...")
        try:
            user_selectors = [
                "input[id='username']", "input[name='username']",
                "input[id='user']", "input[name='login']", "input[type='email']",
                "input[formcontrolname='email']" # Added common Angular selector
            ]
            pass_selectors = [
                "input[id='password']", "input[name='password']",
                "input[id='pwd']", "input[type='password']",
                "input[formcontrolname='password']"
            ]
 
            user_field = None
            for selector in user_selectors:
                try:
                    user_field = self.driver.find_element(By.CSS_SELECTOR, selector)
                    if user_field.is_displayed(): break
                except: continue

            pass_field = None
            for selector in pass_selectors:
                try:
                    pass_field = self.driver.find_element(By.CSS_SELECTOR, selector)
                    if pass_field.is_displayed(): break
                except: continue

            if user_field and pass_field:
                user_field.clear()
                user_field.send_keys(self.config.USERNAME)
                pass_field.clear()
                pass_field.send_keys(self.config.PASSWORD)
                logger.info("Credentials filled using explicit ID/Name selectors.")
                return
        except Exception as e:
            logger.warning(f"Explicit selector strategy failed: {e}. Trying positional fallback.")

        # Strategy 2: Fallback to Positional
        logger.info("Falling back to positional input detection.")
        inputs = self.wait.until(
            lambda d: [i for i in d.find_elements(By.TAG_NAME, "input")
                        if i.is_displayed() and i.get_attribute('type') not in ['hidden', 'submit', 'button', 'checkbox', 'radio']]
        )
 
        login_inputs = [
            inp for inp in inputs
            if "search" not in (inp.get_attribute("name") or "").lower()
            and "tenant" not in (inp.get_attribute("id") or "").lower()
        ]

        if len(login_inputs) >= 2:
            login_inputs[0].clear()
            login_inputs[0].send_keys(self.config.USERNAME)
            login_inputs[1].clear()
            login_inputs[1].send_keys(self.config.PASSWORD)
        else:
            raise Exception("Could not identify Username/Password fields by ID or Position.")

    def submit_login(self):
        """ YOUR TESTED LOGIC """
        logger.info("Attempting to submit login form...")
        button_selectors = [
            "//*[@id='submit']",
            "//button[@id='submit']",
            "//button[@type='submit']",
            "//input[@type='submit']",
            "//button[contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'login')]",
            "//button[contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'submit')]",
            "//a[contains(@class, 'btn') and contains(@href, 'login')]"
        ]

        clicked = False
        for xpath in button_selectors:
            try:
                btn = WebDriverWait(self.driver, 0.5).until(
                    EC.element_to_be_clickable((By.XPATH, xpath))
                )
                logger.info(f"Found submit element via: {xpath}. Clicking.")
                self.kendo.safe_click(btn)
                clicked = True
                break
            except Exception:
                continue

        if not clicked:
            logger.warning("No explicit submit button found. Pressing ENTER on password field.")
            try:
                password_field = self.driver.find_element(By.CSS_SELECTOR, "input[type='password']")
                password_field.send_keys(Keys.ENTER)
            except Exception as e:
                logger.error(f"Failed to submit via ENTER key: {e}")

    def _dump_all_storage(self) -> Dict[str, str]:
        """ REQUIRED FOR ZAP: Grabs tokens so we can inject them later """
        return self.driver.execute_script("""
            var items = {};
            try {
                for (var i = 0; i < localStorage.length; i++) {
                    var k = localStorage.key(i);
                    items['LS_' + k] = localStorage.getItem(k);
                }
            } catch(e) {}
            try {
                for (var i = 0; i < sessionStorage.length; i++) {
                    var k = sessionStorage.key(i);
                    items['SS_' + k] = sessionStorage.getItem(k);
                }
            } catch(e) {}
            return items;
        """)

    def login(self) -> Dict[str, Any]:
        """ Returns the Dict needed by zap_active_scan.py """
        auth_data = {"cookies": [], "tokens": {}}
        
        try:
            logger.info(f"Navigating to: {self.config.LOGIN_URL}")
            self.driver.get(self.config.LOGIN_URL)
            self.bypass_ssl_warning()
 
            self.fill_credentials()
 
            # Tenant selection logic
            if self.config.TENANT_VALUE:
                try:
                    tenant_xpath = f"//kendo-combobox[@id='{self.config.TENANT_IDENTIFIER}' or @data-cy='{self.config.TENANT_IDENTIFIER}']"
                    elements = self.driver.find_elements(By.XPATH, tenant_xpath)
                    if elements and elements[0].is_displayed():
                        self.kendo.kendo_search_and_select(self.config.TENANT_IDENTIFIER, self.config.TENANT_VALUE)
                except Exception:
                    logger.info("Tenant interaction skipped.")

            self.submit_login()
 
            # Success check
            logger.info("Waiting for redirection or storage...")
            try:
                WebDriverWait(self.driver, 15).until(
                    lambda d: d.current_url != self.config.LOGIN_URL or d.execute_script("return localStorage.length > 0;")
                )
            except Exception:
                logger.warning("Timeout waiting for redirect/storage.")

            # --- REQUIRED FOR ZAP: Capture the Tokens ---
            time.sleep(5) 
            auth_data["cookies"] = self.driver.get_cookies()
            auth_data["tokens"] = self._dump_all_storage()

            logger.info(f"Login Flow Completed. Captured {len(auth_data['cookies'])} cookies and {len(auth_data['tokens'])} tokens.")
            return auth_data
 
        except Exception as e:
            logger.error("Login process encountered an error: %s", e)
            try:
                self.driver.save_screenshot("login_debug.png")
            except: pass
            return auth_data
        finally:
            self.driver.quit()

if __name__ == "__main__":
    try:
        print("--- Defender Automation Setup ---")
        default_url = "https://practicetestautomation.com/practice-test-login/"
        url_input = input(f"Enter Login URL (default: {default_url}): ").strip()
        login_url = url_input if url_input else default_url
 
        username = input("Enter Username: ").strip()
        password = getpass.getpass("Enter Password: ").strip()
        tenant = input("Enter Tenant Value (Leave empty to skip): ").strip()

        config = AppConfig(
            LOGIN_URL=login_url,
            USERNAME=username,
            PASSWORD=password,
            TENANT_VALUE=tenant
        )
        DefenderAutomation(config).login()
    except KeyboardInterrupt:
        sys.exit(0)