package nessusRPC

import (
        "crypto/tls"
        "encoding/xml"
        "errors"
        "io/ioutil"
        "log"
        "net/http"
        "net/url"
        "regexp"
)

func request(uri string, postData map[string]string, c *Contents) (b []byte) {
        host_url := "https://" + c.hostName + ":" + c.port + "/"
        nessus_url := host_url + uri
        client := client_setup()
        policyID := postData["policyID"]
        scanName := postData["scanName"]
        target := postData["target"]
        report := postData["report"]
        uuid := postData["scan_uuid"]
        resp, err := client.PostForm(nessus_url, url.Values{"token": {c.Token},
                "policy_id": {policyID}, "scan_name": {scanName},
                "target": {target}, "report": {report}, "scan_uuid": {uuid}})
        defer resp.Body.Close()
        if err != nil {
                log.Fatal(err)
        }
        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                log.Fatal(err)
        }
        return body
}

func client_setup() (client http.Client) {
        tr := &http.Transport{
                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        }
        return http.Client{Transport: tr}
}

type server struct {
        hostName string
        port     string
}

type Contents struct {
        Token   string  `xml:"contents>token"`
        Name    string  `xml:"contents>user>name"`
        Admin   bool    `xml:"contents>user>admin"`
        server
}

// Trys to log into nessus
func Login(user, pass, host, port string) (c *Contents, err error) {
        reg, err := regexp.Compile(`Invalid login`)
        if err != nil {
                log.Fatal(err)
        }
        client := client_setup()
        reply := &Contents{}
        reply.hostName = host
        reply.port = port
        nessus_url := "https://" + host + ":" + port + "/"
        resp, err := client.PostForm(nessus_url+"login",
                url.Values{"login": {user}, "password": {pass}})
        if err != nil {
                log.Fatal(err)
        }
        defer resp.Body.Close()
        body, err := ioutil.ReadAll(resp.Body)
        if reg.MatchString(string(body)) == true {
                return nil, errors.New("Issue logging into the server")
        }
        if err != nil {
                log.Fatal(err)
        }
        xml.Unmarshal(body, &reply)
        return reply, nil
}

type policyName struct {
        PolicyNames []string `xml:"contents>policies>policy>policyName"`
}

// Returns a slice of policy names
func (content Contents) ListPolicyName() (r []string) {
        postData := make(map[string]string)
        body := request("policy/list", postData, &content)
        var reply policyName
        xml.Unmarshal(body, &reply)
        return reply.PolicyNames
}

type policyID struct {
        PolicyID []string `xml:"contents>policies>policy>policyID"`
}

// Returns a slice of policy id's
func (content Contents) ListPolicyID() (r []string) {
        postData := make(map[string]string)
        body := request("policy/list", postData, &content)
        var reply policyID
        xml.Unmarshal(body, &reply)
        return reply.PolicyID
}

// Returns XML file of reports
func (content Contents) ReportsList() (b []byte) {
        postData := make(map[string]string)
        body := request("report/list", postData, &content)
        return body
}

type reportList struct {
        ID        []string `xml:"contents>reports>report>name"`
        ScanName  []string `xml:"contents>reports>report>readableName"`
        Status    []string `xml:"contents>reports>report>status"`
        TimeStamp []string `xml:"contents>reports>report>timestamp"`
}

// Returns a struct of data that contains all the id's, scan names
// scan status and the time stamp of when it was completed
func (content Contents) ReportsListAll() (r *reportList) {
        postData := make(map[string]string)
        body := request("report/list", postData, &content)
        var reply reportList
        xml.Unmarshal(body, &reply)
        return &reply
}

type uuid struct {
        UID string `xml:"contents>scan>uuid"`
}

// Starts a new scan and returns the scans uuid
func (content Contents) StartScan(policyID, scanName, target string) (r string) {
        postData := make(map[string]string)
        postData["policyID"] = policyID
        postData["scanName"] = scanName
        postData["target"] = target
        body := request("scan/new", postData, &content)
        var reply uuid
        xml.Unmarshal(body, &reply)
        return reply.UID
}

// Pause a scan with the given uuid
func (content Contents) PauseScan(uuid string) {
        postData := make(map[string]string)
        postData["scan_uuid"] = uuid
        request("scan/pause", postData, &content)
}

// Resume a scan with the given uuid
func (content Contents) ResumeScan(uuid string) {
        postData := make(map[string]string)
        postData["scan_uuid"] = uuid
        request("scan/resume", postData, &content)
}

// Stop a scan with the given uuid
func (content Contents) StopScan(uuid string) {
        postData := make(map[string]string)
        postData["scan_uuid"] = uuid
        request("scan/stop", postData, &content)
}

type scanStatus struct {
        Name    []string `xml:"contents>reports>report>name"`
        Status  []string `xml:"contents>reports>report>status"`
}

// Returns the status of a scan based on the given uuid number.
func (content Contents) ScanStatus(uuid string) (status string) {
        postData := make(map[string]string)
        body := request("report/list", postData, &content)
        var reply scanStatus
        xml.Unmarshal(body, &reply)
        var stat string
        for x := 0; x <= len(reply.Name); x++ {
                if reply.Name[x] == uuid {
                        stat = reply.Status[x]
                        break
                }
        }
        return stat
}

// Returns a nessus v2 xml report from the given uid
func (content Contents) DownloadFile(uid string) (b []byte) {
        postData := make(map[string]string)
        postData["report"] = uid
        body := request("file/report/download", postData, &content)
        return body
}
