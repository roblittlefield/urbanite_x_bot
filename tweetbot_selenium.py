from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
import time


class TwitterBot:
    def __init__(self):
        self.driver = webdriver.Chrome()

    def send_tweet(self, calls):
        self.driver.get("https://twitter.com/i/flow/login")
        time.sleep(1.5)
        username_input = self.driver.find_element(By.CSS_SELECTOR, 'input[autocomplete="username"]')
        username_input.send_keys("urbanitesf")
        time.sleep(0.1)
        username_input.send_keys(Keys.ENTER)
        time.sleep(1.5)
        password_input = self.driver.find_element(By.CSS_SELECTOR, 'input[autocomplete="current-password"]')
        password_input.send_keys('zorhyh-qyqha6-Maxtob')
        time.sleep(0.1)
        password_input.send_keys(Keys.ENTER)
        time.sleep(2)
        for call in calls:

            # Compose Tweet
            tweet_drafter = self.driver.find_element(By.CLASS_NAME, 'public-DraftStyleDefault-ltr')
            tweet_drafter.send_keys(call)
            time.sleep(0.1)

            # Post Tweet
            post_tweet_btn = self.driver.find_element(By.XPATH, '//*[@id="react-root"]/div/div/div[2]/main/div/div/div/div/div/div[3]/div/div[2]/div[1]/div/div/div/div[2]/div[2]/div[2]/div/div/div[2]/div[3]/div/span/span')
            post_tweet_btn.click()
            time.sleep(1.5)

        # 30-second delay then quit
        time.sleep(30)
        self.driver.quit()
