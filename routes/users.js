const express = require('express');
const router = express.Router();
const axios = require('axios').default;
const request = require('request');

/* IBM API KEY */
//const keyIBM = "fEOOxGITeluTqwW6iiP6_JYlJIw-ncV-k_wsgru_rfRr";

/* keyword with NIST */
const nistKeyword = "https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=vpn";

/* this is the way to access the vulnerabilities public api */
const redHatBaseURL = "https://access.redhat.com/hydra/rest/securitydata";

/* start date with NIST */
const nistStart = "https://services.nvd.nist.gov/rest/json/cves/1.0?modStartDate=2019-01-01T00:00:00:000%20UTC-05:00";

/* parameters that the user can adjust and then used to query the API */
let searchTerm = "vpn";

/* query the NIST api */
router.get("/test", (req, res) => {

  const NIST_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0";

  console.log(req.body)
  axios
  .get(NIST_URL + `?keyword=${searchTerm}`)
        .then((response) => {
          
          const { data } = response;

          const allDescriptions = data.result.CVE_Items.cve.
          description.description_data.value;

          axios
          .get(redHatBaseURL + `/cvrf/${RHSAArray[0]}.json`)
               .then(cvrfData => {
                 console.log("this is about the vulnerability");
               
                 vulnerability = cvrfData.data.cvrfdoc.vulnerability
                 res.send('info about the vulnerability ' + vulnerability);
                 console.log(vulnerability)
                 console.log("this is some notes")
                 notes = cvrfData.data.cvrfdoc.document_notes
                 console.log(notes)
               }).then(() => {
                res.render('index', {
                  title: "Red Hat",
                  body: notes.note[0]
                })
               })
         
        })
})

module.exports = router;
