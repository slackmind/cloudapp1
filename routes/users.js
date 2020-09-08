const express = require('express');
const router = express.Router();
const axios = require('axios').default;

/* IBM API KEY */
//const keyIBM = "fEOOxGITeluTqwW6iiP6_JYlJIw-ncV-k_wsgru_rfRr";

/* parameters that the user can adjust and then used to query the API */
let daysAgo;
let vulnerability;
let notes;

/* store the returned vulnerabilities */
let RHSAArray = [];

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource or two');
});


/* query the redhat api */
router.get("/test", (req, res, next) => {

  /* this is the way to access the vulnerabilities public api */
const redHatBaseURL = "https://access.redhat.com/hydra/rest/securitydata";

/* nist CVE database */
const nistBaseURL = "https://services.nvd.nist.gov/rest/json/cves/1.0";

/* start date with NIST */
const nistStart = "https://services.nvd.nist.gov/rest/json/cves/1.0?modStartDate=2019-01-01T00:00:00:000%20UTC-05:00";

/* keyword with NIST */
const nistKeyword = "https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=vpn";

  console.log(req.body)
  axios
  .get(redHatBaseURL + `/cvrf.json?created_days_ago=${daysAgo}`)
        .then((response) => {
          if(response.status === 400){
            res.status(400).send({"message": "error"})
            res.send('not good - error 404');
          }

          response.data.map(d => RHSAArray.push(d.RHSA))

          axios
          .get(redHatBaseURL + `/cvrf/${RHSAArray[0]}.json`)
               .then(cvrfData => {
                 console.log("this is about the vulnerability");
                 let description = nistData.result.CVE_Items.cve.
                 description.description_data.value;
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
