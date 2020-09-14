var express = require('express');
var router = express.Router();
const axios = require('axios').default;
const Joi = require('joi'); // input validation
//const validator = require('express-joi-validation').createValidator({})

router.get('/searchterm', function (req, res) {

      console.log(req.query);
      // define validation schema
      const schema = Joi.object({
        keyword: Joi.string().alphanum().min(3).max(16).required(),
        resultNum: Joi.number().min(1).max(20).positive().integer().required(),
      });

      // validate the request data against the schema
      let holdInput = schema.validate(req.query);
      console.log("the input is  " + JSON.stringify(holdInput));
      // check if anything went wrong
      if (holdInput.error) {
        let errorMessage = holdInput.error.details[0].message;
        console.log("error is " + errorMessage);
        // error page
        res.render('error', {
          message: errorMessage,
        });
      } else {
        // assign values
        let keyword = holdInput.value.keyword;
        let resultNum = holdInput.value.resultNum;

        
        /* NIST CVE API URL  */
        const NIST_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0";
        let keywordSearch = `?keyword=${keyword}`;
        let numResults = `&resultsPerPage=${resultNum}`;

        axios
          .get(NIST_URL + keywordSearch + numResults)
          .then((response) => {
              //console.log('check that this part works')

              // save the response to an object
              let {
                data
              } = response;
              let infoArray = [];
              let infoArraySize = data.result.CVE_Items.length;
          
              if (infoArraySize > 0) {
                let i;
                for (i = 0; i < infoArraySize; i++) {
                  let tempObj = {}
                  tempObj = data.result.CVE_Items[i].cve.description.description_data[0].value;
                  infoArray.push(tempObj);
                  console.log("iterating");
                  //console.log(infoArray[i]);
                }
              }

              // show the 
              res.render('searchterm', {
                  searchedFor: keyword,
                  sometext: infoArray,
                })

              }).catch(err => {
                  if (err.response) {
                    let errorMessage = "5__ / 4__ error";

                    res.render('error', {
                      message: errorMessage,
                      moretext: err
                    });
                    
                  } else if (err.request) {
                    let errorMessage = "Something went wrong with response or request";

                    res.render('error', {
                      message: errorMessage,
                      moretext: err
                    });
                  }
                  let errorMessage = "Axios error";

                    res.render('error', {
                      message: errorMessage,
                      moretext: err
                    });
                })
            }
          });

      router.get('/timeframe', function (req, res) {

        console.log(req.query);

        // define validation schema
      const schema = Joi.object({
        startMonth: Joi.number().min(1).max(12).positive().integer().required(),
        startYear: Joi.number().min(1995).max(2020).positive().integer().required(),
        endMonth: Joi.number().min(1).max(12).positive().integer(),
        endYear: Joi.number().min(Joi.ref('startYear')).max(2020).positive().integer(),
        resultNum: Joi.number().min(1).max(10).positive().integer(),
      });

      // validate the request data against the schema
      let holdInput = schema.validate(req.query);
      console.log("the input is  " + JSON.stringify(holdInput));

      // check if anything went wrong
      if (holdInput.error) {
        let errorMessage = holdInput.error.details[0].message;
        console.log("error is " + errorMessage);
        // error page
        res.render('error', {
          message: errorMessage,
        });
      } else {
        console.log("ok without error");
        // assign values
        let startMonth = holdInput.value.startMonth;
        let startYear = holdInput.value.startYear;
        let endMonth = holdInput.value.endMonth;
        let endYear = holdInput.value.endYear;
        let resultNum = holdInput.value.resultNum;

        
        /* NIST CVE API URL  */
        const NIST_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0";
        let startTime = `?pubStartDate=${startYear}-${startMonth}-01T00:00:00:000 UTC-05:00`;
        let endTime = `?pubStartDate=${endYear}-${endMonth}-01T00:00:00:000 UTC-05:00`;
        let numResults = `&resultsPerPage=${resultNum}`;
        console.log("maybe not");
        axios
          .get(NIST_URL + startTime + endTime + numResults)

          .then((response) => {
            console.log('got here')

            // save the response to an object
            let {
              data
            } = response;
            console.log('attempt to display data');

            let infoArray = [];
              let infoArraySize = data.result.CVE_Items.length;
          
              if (infoArraySize > 0) {
                let i;
                for (i = 0; i < infoArraySize; i++) {
                  let tempObj = {}
                  tempObj = data.result.CVE_Items[i].cve.description.description_data[0].value;
                  infoArray.push(tempObj);
                  console.log("iterating");
                  //console.log(infoArray[i]);
                }
              }








            res.render('timeframe', {
              title: 'Update',
              sometext: infoArray,
              title2: 'Check a file',
              //info: allDescriptions
            });

          }).catch(err => {
            if (err.response) {
              let errorMessage = "5__ / 4__ error";

              res.render('error', {
                message: errorMessage,
                moretext: err
              });
              
            } else if (err.request) {
              let errorMessage = "Something went wrong with response or request";

              res.render('error', {
                message: errorMessage,
                moretext: err
              });
            } else {
            let errorMessage = "Axios error";

              res.render('error', {
                message: errorMessage,
                moretext: err
              });
            }
          })

          // end of error
        }
      });

      /* GET home page. */
      router.get('/', function (req, res) {

        res.render('index', {
          title: "Find keyword regarding Vulnerabilities",
          title2: "Check a file's hash",
          //info: allDescriptions
        });
      });

      router.get('/checkhash', function (req, res) {

        console.log(req.query);
        let md5hash = req.query.inputHash;

        // from https://virusshare.com/hashfiles/VirusShare_00000.md5 and 
        // from https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html
        // other ideas https://www.cisecurity.org/blog/top-10-malware-january-2019/
        let testHash1 = "10c027b28bfb9c569268746dd805fa7f";
        let testHash2 = "ffb456a28adf28a05af5746f996a96dc";
        let wannaCry1 = "db349b97c37d22f5ea1d1841e3c89eb4";

        /* VIRUS TOTAL API URL  */
        const VIRUS_TOTAL_URL = "https://www.virustotal.com/vtapi/v2/file/report";
        const vtKey = '?apikey=ed88a13aa2d037961fe2150650a49f970b766f3151e684ecbbfb22f04b3d50ca';
        let vtDomain = `&resource=${md5hash}`;

        axios
          .get(VIRUS_TOTAL_URL + vtKey + vtDomain)
          .then((response) => {
            console.log('vt api')

            // save the response to an object
            let {
              data
            } = response;

            // best report summaries
            let symantecReport = data.scans.Symantec.result;
            let sophosReport = data.scans.Sophos.result;
            let kasperskyReport = data.scans.Kaspersky.result;
            let alibabaReport = data.scans.Alibaba.result;
            let trendmicroReport = data.scans.TrendMicro.result;

            // news api key
            let dummySearch = "apple";
            const NEWS_API_URL = "https://newsapi.org/v2/everything";
            const newsKey = "c61555335ae647768b810bcdeef93736";
            let newsQuery = `?q=${dummySearch}&apiKey=${newsKey}`
            console.log("aiya");



            axios
              .get(NEWS_API_URL + newsQuery)
              .then((response2) => {

                console.log("ok we made it");
                let {
                  data2
                } = response2;
                let textdata2 = JSON.stringify(data2);
                console.log(textdata2);
              })







            res.render('checkhash', {
              hashSearched: md5hash,
              hashReport1: symantecReport,
              hashReport2: sophosReport,
              hashReport3: kasperskyReport,
              hashReport4: alibabaReport,
              hashReport5: trendmicroReport,
              /*newsReport: okNowNews */
            });

          })

          // error handling
          .catch(err => {
            if (err.response) {
              console.log("5xx/4xx error");
              console.log(err);
              res.render('error', {
                message: "an error occured"
              });
            } else if (err.request) {
              console.log("something went wrong with response or request");
              console.log(err);
            }
            console.log(err);
            console.log("something went wrong, axios error");
          })
      })

      router.post('/', function (req, res) {
        console.log(req.body.selectDays);
        console.log(req.body.description);
        res.send('Post page');
      });

      module.exports = router;