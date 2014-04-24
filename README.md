nessus-rpc
==========

Interact with Nessus REST

## Example Usage

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
            // Start Scan
            uid := nessus.StartScan("-5", "testing", "localhost")
            fmt.Println("Scan Status")
            status := nessus.ScanStatus(uid)
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
    
    func scanStatus(uid, status string, nessus *nessusRPC.Contents) string {
            if status != "completed" {
                    fmt.Println(status)
                    time.Sleep(time.Second * 5)
            } else {
                    return "completed"
            }
            s := nessus.ScanStatus(uid)
            return scanStatus(uid, s, nessus)
    }

### Package provides

1. ListPolicyName
  *  Returns a slice of policy names
2. ListPolicyID
  * Returns a slice of policy id's
3. ReportsList
  * Returns XML file of reports
4. ReportListAll
  * Returns a struct of data that contains all the id's, scan names, scan status and the time stamp of when it was completed
5. StartScan
  * Starts a new scan and returns teh scans uuid
6. ScanStatus
  * Returns the status of a scan based on the given uuid number
7. DownloadFile
  * Retruns a nessusv2 xml report from the given uid 
