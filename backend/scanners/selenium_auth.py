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
    TENANT_DATA_CY: str = "tenant"   # <-- IMPORTANT
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

    def kendo_search_bar(self, data_cy: str, value: str):
        """
        EXACT Java behaviour:
        click → type → ENTER
        Used for Tenant (IDEXDEMO)
        """
        container_xpath = f"//*[@data-cy='{data_cy}']"
        input_xpath = f"{container_xpath}//input"

        logger.info("Opening tenant dropdown")
        container = self.wait.until(
            EC.visibility_of_element_located((By.XPATH, container_xpath))
        )
        self.safe_click(container)

        logger.info("Typing tenant value")
        input_box = self.wait.until(
            EC.visibility_of_element_located((By.XPATH, input_xpath))
        )
        input_box.clear()
        input_box.send_keys(value)
        time.sleep(0.5)
        input_box.send_keys(Keys.ENTER)


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
        if len(inputs) < 2:
            raise RuntimeError("Username/Password fields not found")

        inputs[0].clear()
        inputs[0].send_keys(self.config.USERNAME)

        inputs[1].clear()
        inputs[1].send_keys(self.config.PASSWORD)

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

            # 🔥 THIS IS THE FIX
            self.kendo.kendo_search_bar(
                self.config.TENANT_DATA_CY,
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
