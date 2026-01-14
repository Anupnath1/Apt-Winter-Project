# selenium_auth.py
# WIRED VERSION — Kendo search-based Tenant selection (IDEXDEMO)
# Production-safe, deterministic, no placeholders

import sys
import time
import logging
from dataclasses import dataclass

from selenium import webdriver
from selenium.webdriver.chrome.webdriver import WebDriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.remote.webelement import WebElement
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException


# ---------------- LOGGING ----------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


# ---------------- CONFIG ----------------

@dataclass(frozen=True)
class AppConfig:
    LOGIN_URL: str = "https://defender.aptsoftware.in/login"
    USERNAME: str = "IdexApprover"
    PASSWORD: str = "IDEXApp@0424"
    TENANT_VALUE: str = "IDEXDEMO"
    TENANT_IDENTIFIER: str = "tenantid" 
    TIMEOUT: int = 30
    HEADLESS: bool = False


# ---------------- KENDO UTILS ----------------

class KendoUtils:
    def __init__(self, driver: WebDriver, timeout: int):
        self.driver = driver
        self.wait = WebDriverWait(driver, timeout)

    def safe_click(self, element: WebElement):
        try:
            self.wait.until(EC.element_to_be_clickable(element))
            element.click()
        except Exception:
            self.driver.execute_script("arguments[0].click();", element)

    def kendo_search_and_select(self, identifier: str, value: str):
        """
        Handles the Kendo Combobox structure.
        Fix: Explicitly clicks the arrow button to force the dropdown open.
        """
        try:
            # 1. FIND WRAPPER (kendo-combobox)
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
            
            # 2. OPEN DROPDOWN (Click the arrow button)
            # Using the class visible in your screenshot: .k-input-button
            logger.info("Clicking dropdown arrow to force open...")
            try:
                arrow_btn = wrapper.find_element(By.CSS_SELECTOR, ".k-input-button")
                self.safe_click(arrow_btn)
                time.sleep(0.5) # Wait for animation
            except Exception:
                logger.warning("Could not click arrow button, trying input directly.")

            # 3. FIND INPUT & TYPE
            input_element = wrapper.find_element(By.TAG_NAME, "input")
            input_element.clear()
            logger.info(f"Typing value: {value}")
            
            # Type slowly to trigger Kendo events
            for char in value:
                input_element.send_keys(char)
                time.sleep(0.05)
            
            # 4. WAIT FOR POPUP (Grid Cells or List Items)
            # Try both 'gridcell' (standard grid) and 'option' (standard combobox) roles
            item_xpath = "//*[@role='gridcell' or @role='option']"
            
            logger.info("Waiting for dropdown suggestions...")
            self.wait.until(EC.presence_of_element_located((By.XPATH, item_xpath)))
            
            suggestions = self.driver.find_elements(By.XPATH, item_xpath)
            logger.info(f"Found {len(suggestions)} suggestions.")

            match_found = False
            for item in suggestions:
                if item.text.strip() == value:
                    logger.info(f"Match found: '{item.text}'. Clicking.")
                    self.safe_click(item)
                    match_found = True
                    break
            
            if not match_found:
                logger.warning(f"No exact match found for '{value}'. Pressing ENTER.")
                input_element.send_keys(Keys.ENTER)

        except Exception as e:
            logger.error(f"Kendo interaction failed for '{identifier}': {e}")
            raise


# ---------------- MAIN AUTOMATION ----------------

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
        options.add_argument("--start-maximized")
        options.page_load_strategy = "eager"

        if self.config.HEADLESS:
            options.add_argument("--headless=new")

        return webdriver.Chrome(options=options)

    def bypass_ssl_warning(self):
        try:
            time.sleep(2)
            if "not private" in self.driver.page_source.lower():
                self.driver.find_element(By.TAG_NAME, "body").send_keys("thisisunsafe")
        except Exception:
            pass

    def fill_credentials(self):
        logger.info("Filling username/password")
        inputs = self.wait.until(
            lambda d: [i for i in d.find_elements(By.TAG_NAME, "input") if i.is_displayed()]
        )
        # Filter out the tenant input if it's already visible to ensure we get user/pass
        login_inputs = [inp for inp in inputs if "tenant" not in inp.get_attribute("outerHTML")]

        if len(login_inputs) < 2:
            # Fallback
            login_inputs = inputs

        login_inputs[0].clear()
        login_inputs[0].send_keys(self.config.USERNAME)

        login_inputs[1].clear()
        login_inputs[1].send_keys(self.config.PASSWORD)

    def submit_login(self):
        submit_btn = self.wait.until(
            EC.element_to_be_clickable(
                (By.XPATH, "//button[@type='submit' or contains(.,'Login')]")
            )
        )
        submit_btn.click()

    def login(self):
        try:
            logger.info("Opening login page")
            self.driver.get(self.config.LOGIN_URL)

            self.bypass_ssl_warning()
            self.fill_credentials()

            # Using Updated Kendo Logic
            self.kendo.kendo_search_and_select(
                self.config.TENANT_IDENTIFIER,
                self.config.TENANT_VALUE
            )

            self.submit_login()

            self.wait.until(lambda d: self.config.LOGIN_URL not in d.current_url)
            logger.info("Login SUCCESS")

            time.sleep(5)

        except Exception as e:
            logger.error("Login FAILED: %s", e)
            self.driver.save_screenshot("login_error.png")
            sys.exit(1)
        finally:
            self.driver.quit()


# ---------------- ENTRY POINT ----------------

if __name__ == "__main__":
    DefenderAutomation(AppConfig()).login()