let express = require('express');
let router = express.Router();
const axios = require('axios').default;

/* this is the way to access the vulnerabilities public api */
const redHatBaseURL = "https://access.redhat.com/hydra/rest/securitydata";


/* IBM API KEY */
const keyIBM = fEOOxGITeluTqwW6iiP6_JYlJIw-ncV-k_wsgru_rfRr;

/* parameters that the user can adjust and then used to query the API */
let daysAgo = 5;
let vulnerability;
let notes;

/* store the returned vulnerabilities */
let RHSAArray = [];

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource or two');
});


/* for the test web page */
router.get("/test", (req, res, next) => {
  axios.get(redHatBaseURL + `/cvrf.json?created_days_ago=${daysAgo}`)
        .then((response) => {
          if(response.status === 400){
            res.status(400).send({"message": "error"})
            res.send('not good - error 404');
          }
          response.data.map(d => RHSAArray.push(d.RHSA))
          axios.get(redHatBaseURL + `/cvrf/${RHSAArray[0]}.json`)
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
                  title: "REd Hat",
                  body: notes.note[0]
                })
               })
         
        })
})

module.exports = router;
