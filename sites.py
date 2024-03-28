import requests
import random
import re
import urllib.request
from bs4 import BeautifulSoup
from collections import deque
from html.parser import HTMLParser
from urllib.parse import urlparse
import os
import pandas as pd
import tiktoken
import time
from flask import session
import openai
from openai.embeddings_utils import distances_from_embeddings
import numpy as np
from openai.embeddings_utils import distances_from_embeddings, cosine_similarity



# Regex pattern to match a URL
HTTP_URL_PATTERN = r'^http[s]*://.+'
status_data = {}
# Define root domain to crawl
#full_url = input("Enter a domain :")
#full_url = "https://colibristudi.co/"

# Add this function to check if the URL is accessible
def url_is_accessible(url, homepage_url):
    
    try:
        response = requests.head(url, timeout=10, allow_redirects=True)
        if response.status_code >= 200 and response.status_code < 400:
            if response.url.rstrip('/') == homepage_url.rstrip('/'):
                return False
            return True
    except Exception as e:
        pass
    return False

import re
from urllib.parse import urlparse
import time

HTTP_URL_PATTERN = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"


def get_domain_hyperlinks2(url, depth=1, max_links=100, max_time=60):
    start_time = time.time()
    local_domain = urlparse(url).netloc
    homepage_url = "https://" + local_domain
    clean_links = {url}  # Initialize the set with the submitted URL
    hyperlinks = set(get_hyperlinks2(url))

    if depth > 1:
        for link in hyperlinks.copy():
            if time.time() - start_time > max_time:
                break
            sub_hyperlinks = set(get_hyperlinks2(link))
            hyperlinks.update(sub_hyperlinks)

    for link in hyperlinks:
        if time.time() - start_time > max_time:
                break
        clean_link = None

        if re.search(HTTP_URL_PATTERN, link):
            
            url_obj = urlparse(link)
            if url_obj.netloc == local_domain:
                clean_link = link
        else:
            if link.startswith("/"):
                link = link[1:]
            elif (
                link.startswith("#")
                or link.startswith("mailto:")
                or link.startswith("mailto:")
                or link.startswith("tel:")
                or link.startswith("whatsapp://send")
            ):
                continue
            clean_link = "https://" + local_domain + "/" + link

        if clean_link is not None:
            if clean_link.endswith("/"):
                clean_link = clean_link[:-1]
                
            # Add this line to check if the link has a fragment identifier or email protection
            parsed_clean_link = urlparse(clean_link)
            if parsed_clean_link.fragment or "/cdn-cgi/l/email-protection" in clean_link:
                continue

            if url_is_accessible(clean_link, homepage_url) and clean_link != homepage_url:
                
                clean_links.add(clean_link)
                print(clean_link)  # Add the link to the set
                if len(clean_links) >= max_links:
                    break

    return list(clean_links)  # Convert the set to a list before returning


def get_hyperlinks2(url):
# Try to open the URL and read the HTML
    try:
        proxies_list = [
                '152.89.10.117:8800',
                '192.126.244.67:8800',
                '38.154.99.218:8800',
                '192.126.244.239:8800',
                '38.154.99.182:8800',
                '152.89.10.92:8800',
                '192.126.242.81:8800',
                '38.154.99.206:8800',
                '38.154.99.234:8800',
                '192.126.242.151:8800'
            ]
        user_agent_list = [
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36"
                    ]
        # Shuffle the proxies list
        random.shuffle(proxies_list)

        response = None
        for proxy in proxies_list:
            try:
                proxies = {
                    'http': f'{proxy}',
                    'https': f'{proxy}'
                }
                user_agent = random.choice(user_agent_list)
                headers = {"User-Agent": user_agent}
                response = requests.get(url, proxies=proxies, headers=headers, timeout=15)
                if response.status_code == 200:
                    break
            except requests.exceptions.RequestException:
                pass

        if response and response.status_code == 200:
            html = response.text
        else:
            print('[HYPER] Failed to get the content using all proxies')
            return []

    except Exception as e:
        print(e)
        return []

    # Create the HTML Parser and then Parse the HTML to get hyperlinks
    parser = HyperlinkParser()
    parser.feed(html)

    return parser.hyperlinks
# Create a class to parse the HTML and get the hyperlinks
class HyperlinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        # Create a list to store the hyperlinks
        self.hyperlinks = []

    # Override the HTMLParser's handle_starttag method to get the hyperlinks
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        # If the tag is an anchor tag and it has an href attribute, add the href attribute to the list of hyperlinks
        if tag == "a" and "href" in attrs:
            self.hyperlinks.append(attrs["href"])



def sitefy(hyperlinks, user_id):

    status_data[user_id] = {
        'estimated_time': 0,
        'hyperlinks_processed': 0,
        'hyperlinks_remaining': 0
    }

    local_domain = urlparse(hyperlinks[0]).netloc
    print(f'okay, domain is : {local_domain}')

    # Create a directory to store the text files
    if not os.path.exists("sites/"):
        os.mkdir("sites/")

    if not os.path.exists("sites/text/"):
        os.mkdir("sites/text/")

    if not os.path.exists("sites/text/" + local_domain + "/"):
        os.mkdir("sites/text/" + local_domain + "/")

    # Create a directory to store the csv files
    if not os.path.exists("sites/processed"):
        os.mkdir("sites/processed")

    def crawl(hyperlinks):
        start_time = time.time()
        processed_urls = 0

        # Create an empty string to store the combined text from all pages
        combined_text = ""

        # Iterate through the hyperlinks list
        for url in hyperlinks:
            # Get the next URL from the list
            print(url)  # for debugging and to see the progress
            shrinkedpath = url[8:].replace("/", "_")
            # Save text from the url to a <url>.txt file
            with open('sites/text/' + local_domain + '/' + shrinkedpath[:50] + "-SHORTED"  + ".txt", "w", encoding="UTF-8") as f:

                # Get the text from the URL using BeautifulSoup# Get the text from the URL using BeautifulSoup
               
                req = requests.get("https://checkip.instantproxies.com/")
                print(req.text)
                                
                proxies_list = [
                    '152.89.10.117:8800',
                    '192.126.244.67:8800',
                    '38.154.99.218:8800',
                    '192.126.244.239:8800',
                    '38.154.99.182:8800',
                    '152.89.10.92:8800',
                    '192.126.242.81:8800',
                    '38.154.99.206:8800',
                    '38.154.99.234:8800',
                    '192.126.242.151:8800'
                ]

                # Shuffle the proxies list
                random.shuffle(proxies_list)

                response = None
                for proxy in proxies_list:
                    print(f'using proxy : {proxy}')
                    try:
                        user_agent_list = [
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36"
                        ]
                        proxies = {
                            'http': f'{proxy}',
                            'https': f'{proxy}'
                        }
                        req = requests.get("https://checkip.instantproxies.com/",proxies=proxies, timeout=15)
                        print("using proxy now ...")
                        print(req.text)
                        user_agent = random.choice(user_agent_list)
                        headers = {"User-Agent": user_agent}
                        response = requests.get(url, proxies=proxies, headers=headers, timeout=15)
                        if response.status_code == 200:
                            break
                    except requests.exceptions.RequestException:
                        pass

                if response and response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    text = soup.get_text()

                else:
                    text = ''
                    print('[CRAWL] Failed to get the content using all proxies')

                    
                # soup = BeautifulSoup(requests.get(url).text, "html.parser")

                # Get the text but remove the tags
                # text = soup.get_text()

                # If the crawler gets to a page that requires JavaScript, it will stop the crawl
                # if ("You need to enable JavaScript to run this app." in text):
                #     print("Unable to parse page " + url + " due to JavaScript being required")
                
                # # Otherwise, write the text to the file in the text directory
                # f.write(text)

                # # Add the text to the combined_text
                combined_text += "\n\n" + text

            # Update the processed URLs count
            processed_urls += 1

            # Calculate the average time per URL and estimate the remaining time
            average_time_per_url = (time.time() - start_time) / processed_urls
            remaining_urls = len(hyperlinks) - processed_urls
            estimated_time_remaining = average_time_per_url * remaining_urls

            status_data[user_id] = {
                'estimated_time': estimated_time_remaining,
                'hyperlinks_processed': processed_urls,
                'hyperlinks_remaining': remaining_urls + processed_urls
            }

            print(f"Processed URLs: {processed_urls}, Remaining URLs: {remaining_urls}")
            print(f"Estimated time remaining: {estimated_time_remaining:.2f} seconds")

        return combined_text

    # Call the crawl function with the hyperlinks list
    text = crawl(hyperlinks)

    del status_data[user_id]
    return text, local_domain
    