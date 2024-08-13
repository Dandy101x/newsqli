package main

import (
    "flag"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "strings"
    "sync"
    "time"
)

func performRequest(url, payload, cookie string) (bool, string, float64, string) {
    urlWithPayload := strings.Replace(url, "*", payload, -1)
    startTime := time.Now()

    client := &http.Client{}
    req, err := http.NewRequest("GET", urlWithPayload, nil)
    if err != nil {
        return false, urlWithPayload, 0, err.Error()
    }
    if cookie != "" {
        req.AddCookie(&http.Cookie{Name: "cookie", Value: cookie})
    }
    
    resp, err := client.Do(req)
    if err != nil {
        return false, urlWithPayload, 0, err.Error()
    }
    defer resp.Body.Close()

    responseTime := time.Since(startTime).Seconds()
    if resp.StatusCode >= 200 && resp.StatusCode < 300 {
        return true, urlWithPayload, responseTime, ""
    }
    return false, urlWithPayload, responseTime, fmt.Sprintf("HTTP status code: %d", resp.StatusCode)
}

func processPayloads(url string, payloads []string, cookie string, outputFile string, wg *sync.WaitGroup) {
    defer wg.Done()

    for _, payload := range payloads {
        var payloadsToTest []string
        if strings.Contains(url, "*") {
            for _, p := range strings.Split(payload, ",") {
                payloadsToTest = append(payloadsToTest, strings.Replace(url, "*", p, -1))
            }
        } else {
            payloadsToTest = append(payloadsToTest, url+payload)
        }

        for _, testPayload := range payloadsToTest {
            success, urlWithPayload, responseTime, errorMessage := performRequest(testPayload, "", cookie)
            resultLine := ""

            if responseTime >= 10 {
                resultLine = fmt.Sprintf("✓ SQLi Found! URL: %s - Response Time: %.2f seconds", urlWithPayload, responseTime)
                fmt.Printf("\033[92m%s\033[0m\n", resultLine)
            } else {
                resultLine = fmt.Sprintf("✗ Not Vulnerable. URL: %s - Response Time: %.2f seconds", urlWithPayload, responseTime)
                fmt.Printf("\033[91m%s\033[0m\n", resultLine)
            }

            if outputFile != "" {
                file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
                if err != nil {
                    log.Println("Error opening file:", err)
                    return
                }
                defer file.Close()

                _, err = file.WriteString(resultLine + "\n")
                if err != nil {
                    log.Println("Error writing to file:", err)
                }
            }
        }
    }
}

func main() {
    urlPtr := flag.String("url", "", "Single URL to scan.")
    listPtr := flag.String("list", "", "Text file containing a list of URLs to scan.")
    payloadsPtr := flag.String("payloads", "", "Text file containing the payloads to append to the URLs.")
    cookiePtr := flag.String("cookie", "", "Cookie to include in the GET request.")
    threadsPtr := flag.Int("threads", 0, "Number of concurrent threads (0-10).")
    outputPtr := flag.String("output", "", "File to save vulnerable results.")
    flag.Parse()

    if *urlPtr == "" && *listPtr == "" {
        log.Fatal("Either --url or --list must be specified.")
    }

    var urls []string
    if *urlPtr != "" {
        urls = []string{*urlPtr}
    } else {
        content, err := ioutil.ReadFile(*listPtr)
        if err != nil {
            log.Fatalf("Error reading file: %v", err)
        }
        urls = strings.Split(string(content), "\n")
    }

    content, err := ioutil.ReadFile(*payloadsPtr)
    if err != nil {
        log.Fatalf("Error reading payloads file: %v", err)
    }
    payloads := strings.Split(string(content), "\n")

    fmt.Println(" ______               __ __ ")
    fmt.Println("|   __ \\-----.-----.|  |__|")
    fmt.Println("|   __ <|__ --|  _  ||  |  |")
    fmt.Println("|______/|_____|__   ||__|__|")
    fmt.Println("                 |__|        ")
    fmt.Println("made by Coffinxp :)")

    var wg sync.WaitGroup
    for _, url := range urls {
        if *threadsPtr == 0 {
            processPayloads(url, payloads, *cookiePtr, *outputPtr, &wg)
        } else {
            wg.Add(1)
            go processPayloads(url, payloads, *cookiePtr, *outputPtr, &wg)
            if len(urls) > 1 {
                time.Sleep(time.Duration(1000 / *threadsPtr) * time.Millisecond)
            }
        }
    }

    if *threadsPtr > 0 {
        wg.Wait()
    }
}