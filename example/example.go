package main

import (
        "fmt"
        "github.com/b00stfr3ak/nessus-rpc"
        "io/ioutil"
        "log"
        "time"
)

func main() {
        // Login to Nessus
        nessus, err := nessusRPC.Login("user", "password", "localhost", "8834")
        if err != nil {
                log.Fatal(err)
        }
        /*   List policy name and id's Avail
             fmt.Println("Listing Policy Name")
             pn := nessus.ListPolicyName()
             fmt.Println(pn)
             fmt.Println("List Policy ID")
             pi := nessus.ListPolicyID()
             fmt.Println(pi)
        */
        // Start Scan
        uid := nessus.StartScan("-5", "testing", "localhost")
        fmt.Println("Scan Status")
        checkStatus(uid, nessus)
        //Pause Scan
        nessus.PauseScan(uid)
        checkStatus(uid, nessus)
        //Resume Scan
        nessus.ResumeScan(uid)
        status := checkStatus(uid, nessus)
        //Stop Scan
        //nessus.StopScan(uid)
        //status := checkStatus(uid, nessus)
        //Check status loop
        scanStatus(uid, status, nessus)
        // Download file
        fmt.Println("Downloading File")
        content := nessus.DownloadFile(uid)
        //fmt.Println(content)
        errs := ioutil.WriteFile("/tmp/dat1", content, 0644)
        if errs != nil {
                log.Fatal(errs)
        }

}

func checkStatus(uid string, nessus *nessusRPC.Contents) string {
        s := nessus.ScanStatus(uid)
        fmt.Println(s)
        return s
}

func scanStatus(uid, status string, nessus *nessusRPC.Contents) string {
        if status != "completed" {
                time.Sleep(time.Second * 5)
        } else {
                return "completed"
        }
        s := checkStatus(uid, nessus)
        return scanStatus(uid, s, nessus)
}
