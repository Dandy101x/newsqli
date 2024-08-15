import argparse
import requests
import time
import threading
import os

def perform_request(url, payload, cookie):
    url_with_payload = url.replace("*", payload)
    start_time = time.time()

    headers = {}
    if cookie:
        headers["Cookie"] = cookie

    try:
        response = requests.get(url_with_payload, headers=headers)
    except requests.RequestException as e:
        return False, url_with_payload, 0, str(e)

    response_time = time.time() - start_time
    if 200 <= response.status_code < 300:
        return True, url_with_payload, response_time, ""
    return False, url_with_payload, response_time, f"HTTP status code: {response.status_code}"

def process_payloads(url, payloads, cookie, output_file):
    for payload in payloads:
        payloads_to_test = []
        if "*" in url:
            for p in payload.split(","):
                payloads_to_test.append(url.replace("*", p))
        else:
            payloads_to_test.append(url + payload)

        for test_payload in payloads_to_test:
            success, url_with_payload, response_time, error_message = perform_request(test_payload, "", cookie)
            result_line = ""

            if response_time >= 10:
                result_line = f"✓ SQLi Found! URL: {url_with_payload} - Response Time: {response_time:.2f} seconds"
                print(f"\033[92m{result_line}\033[0m")
            else:
                result_line = f"✗ Not Vulnerable. URL: {url_with_payload} - Response Time: {response_time:.2f} seconds"
                print(f"\033[91m{result_line}\033[0m")

            if output_file:
                with open(output_file, "a") as f:
                    f.write(result_line + "\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="Single URL to scan.")
    parser.add_argument("-l", "--list", help="Text file containing a list of URLs to scan.")
    parser.add_argument("-p", "--payloads", help="Text file containing the payloads to append to the URLs.")
    parser.add_argument("-c", "--cookie", help="Cookie to include in the GET request.")
    parser.add_argument("-t", "--threads", type=int, help="Number of concurrent threads (0-10).")
    parser.add_argument("-o", "--output", help="File to save vulnerable results.")
    args = parser.parse_args()

    if not args.url and not args.list:
        parser.error("Either --url or --list must be specified.")

    urls = [args.url] if args.url else [line.strip() for line in open(args.list)]

    with open(args.payloads) as f:
        payloads = [line.strip() for line in f]

    print(" ______               __ __ ")
    print("|   __ \\-----.-----.|  |__|")
    print("|   __ <|__ --|  _  ||  |  |")
    print("|______/|_____|__   ||__|__|")
    print("                 |__|        ")
    print("made by Coffinxp :)")

    threads = []
    for url in urls:
        if args.threads == 0:
            process_payloads(url, payloads, args.cookie, args.output)
        else:
            t = threading.Thread(target=process_payloads, args=(url, payloads, args.cookie, args.output))
            threads.append(t)
            t.start()
            if len(urls) > 1:
                time.sleep(1000 / args.threads)

    if args.threads > 0:
        for t in threads:
            t.join()

if __name__ == "__main__":
    main()
