const mysql = require('mysql');
var express = require('express');
var bodyParser = require('body-parser');

// const axios = require('axios');
var app = express();
app.use(express.static(__dirname + '/views'));
app.set('view engine', 'ejs');
var urlencodedParser = bodyParser.urlencoded({ extended: true })
app.use(urlencodedParser);
app.use(bodyParser.json());
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');



//////////////////// override
var methodOverride = require('method-override')
app.use(methodOverride(function (req, res) {
if (req.body && typeof req.body === 'object' && '_method' in req.body) {
    // look in urlencoded POST bodies and delete it
    var method = req.body._method
    delete req.body._method
    return method
}
}));



//////////////// passport ///////////////////////////////////////////////////////////////////////////////////
  const passport = require('passport');
  const passportJWT = require('passport-jwt');
  var ExtractJwt = passportJWT.ExtractJwt;
  var JwtStrategy = passportJWT.Strategy;


  // initialize passport with express
  app.use(passport.initialize());

  var jwtOptions = {}
  jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme('Bearer');  ///// tokenformat will be Bearer <token>,, authomatically extract
  jwtOptions.secretOrKey = 'tasmanianDevil';
  var REFRESH_TOKEN_SECRET = "manthan";

///  //This verifies that the token sent by the user is valid
var strategy = new JwtStrategy(jwtOptions, function(jwt_payload, next) {
    console.log('payload received', jwt_payload);
    // usually this would be a database call:
    mysqlConnection.query("SELECT userid , username , email , password FROM userdata WHERE username =  ? ",[jwt_payload.name], (err, rows, fields) => {
        var user = rows;
        if(user){   // Pass the user details to the next middleware
            next(null, user);
        } else {
             res.redirect('/login');
        }
    })
});


passport.use(strategy);
var user;

app.get("/", (req,res) => {
     res.redirect('/table');
})

app.get("/login",(req,res)=>{
    res.render('login',{messsge:"Welcome"});
})
app.get("/signup",(req,res)=>{
    res.render('register',{messsge:"Welcome"});
})

//////////// Login ///////////////////
app.post("/login", function(req, res) {

mysqlConnection.query("SELECT userid , username , email , password FROM userdata WHERE username =  ? ",[req.body.username], (err, rows, fields) => {
 user = rows[0];
 if(!user){              res.send({message:"No User found,,.."});

    }else{

       console.log(user);

       bcrypt.compare(req.body.password, rows[0].password , async function(err, response){

        if (err){     console.log("Error occured in bcrypt");   }
        if (response == true ){   // Send JWT
            var payload = {name: user.username, email: user.email };
            var token = await jwt.sign( payload , jwtOptions.secretOrKey , { expiresIn:'20s'} ); ///   ,{ expiresIn:'90s'} created accesstoken
            var refreshToken =await jwt.sign( payload ,REFRESH_TOKEN_SECRET); // created refresh token for unlimited times

            await refreshToken.toString(); ///now insert into db
            console.log("Refresh Token before adding  :::::: "+refreshToken);

            mysqlConnection.query("INSERT INTO refreshtoken (refresh_token) values (?) ", [ refreshToken ],async (err, rows, fields) => {
                    console.log("Inserted refresh token in DB ::::::::  "+await rows);
                    console.log("refresh after insert token is in login :::::::::: "+ refreshToken);
                    console.log("token is in login :::::::: "+ token);
                    res.send({ token : token , refreshtoken : refreshToken , message:"You are logged in,." });
            })
               //
    } else {    // response is OutgoingMessage object that server response http request
        return res.send({success: false, message: 'passwords do not match'});
            }
        });
      }
   })
});

//////// token genertaed/////////
app.post('/token', (req, res) => {
    const refreshToken = req.body.token
    console.log("New token is called"+ refreshToken);
    if (refreshToken == null){ return res.sendStatus(401) }
    /// check if token exists or not,,...
    mysqlConnection.query("SELECT refresh_token  FROM refreshtoken WHERE refresh_token =  ? ",[refreshToken], (err, rows, fields) => {
    result = rows[0];
    if(!result){  res.send({messge : " No Token found "}); }
    else{
        jwt.verify(refreshToken,REFRESH_TOKEN_SECRET, (err, user) => {
            if (err) { return res.sendStatus(403);   }
            else {
            console.log(user);
            const accessToken = jwt.sign({name: user.name , email: user.email }, jwtOptions.secretOrKey, { expiresIn: '20s' });
            console.log(accessToken);
            res.send({ accessToken: accessToken })
            }
          })
        }
    })
})


/// logout first check into refesh databse and then delete from it...
app.delete('/logout', (req, res) => {
    mysqlConnection.query("DELETE FROM refreshtoken WHERE refresh_token = ? ",[req.body.token] , (err, rows, fields) =>{
        if(err) return  res.send(err);
        console.log(rows);
         res.send({message:" You are logged out "});
    })
    // refreshTokens = refreshTokens.filter(token => token !== req.body.token)
    // res.sendStatus(204);
});


/// password: dhruvin,shyam,raj--==== dhoom



//// inserting data
app.post('/signup', async (req,res)=>{
    let user = req.body;
    let hashedPassword = await bcrypt.hash(req.body.password, 10)
    var sql = "INSERT INTO userdata (username,email,password) values (?,?,?)";
    mysqlConnection.query(sql, [user.username, user.email, hashedPassword ], (err, rows, fields) => {
        if(!err){
            console.log("User is created");
            res.redirect('/login');
        }
        else{ console.log(err); }
    });
})

////////////////////////////////////////////////////////////////////////////
app.get("/secret", passport.authenticate('jwt', { session: false }), function(req, res){
    res.send({message: "Success! You can not see this without a token"});
 });

app.get('/verify',verifyToken ,(req,res)=>{
    jwt.verify(req.token,jwtOptions.secretOrKey, (err,authData)=>{
        if(err){ ///// user is not authenticated
            res.send("NO");;
            // res.sendStatus(403);
        }else{ ///// user is authenticated
             res.send("YES");;
        }
    });
});
function verifyToken(req,res,next){
    const bearerHeader = req.headers['authorization'];   //GET auth header value
if(typeof bearerHeader !== 'undefined'){       // check if bearer is undefined
    const bearer = bearerHeader.split(' ');    //split at space
    const bearerToken = bearer[1];  // get the token from array
    req.token = bearerToken;   //set the token
    next();  //next middelware
} else {            // forbidden
    res.redirect("NO");
    }
}

////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////



//tablename: learnerdetails,, columns:"learner_id","learner_name","learner_email","course_id"
//mysql details
var mysqlConnection = mysql.createConnection({
    host:'localhost',
    user:'root',
    password: '',
    database: 'learners',
    multipleStatements: true
});

mysqlConnection.connect((err)=> {
    if(!err)
    console.log('Connection Established Successfully');
    else
    console.log('Connection Failed!'+ JSON.stringify(err,undefined,2));
    });

//Establish the server connection
//PORT ENVIRONMENT VARIABLE
const port = process.env.PORT || 8080;
app.listen(port, () => console.log(`Listening on port ${port}..`));


app.get('/table',(req,res)=>{
    var subarray;
    mysqlConnection.query("SELECT subject_id , subject_name FROM subjectdetails", (err, rows, fields) => {
        if(!err){
            // console.log(rows);
            res.render('index2',{subjects:rows});
        }
        else{ console.log(err); }
    });
})


var mesage = "Welcome to student info";

//Creating GET Router to fetch all the learner details from the MySQL Database
app.get('/learners', passport.authenticate('jwt', { session: false }) , (req, res) => {
    mysqlConnection.query("SELECT l.learner_id,l.learner_name,l.learner_email,l.mobile_number,GROUP_CONCAT(s.subject_name) AS 'subjects',GROUP_CONCAT(s.subject_chapter) AS 'chapters',GROUP_CONCAT(s.subject_imp) AS 'imps' FROM learnerdetails l LEFT JOIN sub_rel_learn rl ON rl.learnerid = l.learner_id LEFT JOIN subjectdetails s ON s.subject_id = rl.subjectid WHERE l.deleted = 0 GROUP BY l.learner_id", (err, rows, fields) => {
    if (!err){console.log("record fetched successfully");
    res.send({data:rows});}
    else{
    console.log(err);}
    })
    });


//Router to GET specific learner detail from the MySQL database
app.get('/learners/:id' , (req, res) => {
    mysqlConnection.query("SELECT l.learner_id,l.learner_name,l.learner_email,l.mobile_number,GROUP_CONCAT(s.subject_name) AS 'subjects' FROM learnerdetails l LEFT JOIN sub_rel_learn rl ON rl.learnerid = l.learner_id LEFT JOIN subjectdetails s ON s.subject_id = rl.subjectid  WHERE l.learner_id = ? GROUP BY l.learner_id",[req.params.id], (err, results, fields) => {
    if (!err){
        mysqlConnection.query("SELECT subject_id,subject_name FROM subjectdetails", (err, rows, fields) => {
            console.log(data);
            console.log(rows);
        res.send({data:results, allsub: rows});
     })

    }else{
    console.log(err);}
    })
    });

var mailformat = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
var phoneformat = /^\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})$/;



// add or insert opertaion
app.post('/_insert' , passport.authenticate('jwt', { session: false }) , (req, res) => {
    let learner = req.body;
    var mobile = learner.mobile_number;
    var emailval = learner.learner_email;

if(mobile.match(phoneformat) && emailval.match(mailformat)){
    // valid email and phone



    var subjects = learner.course_Id;
    console.log(learner);
    var sql = "INSERT INTO learnerdetails (learner_name,learner_email,mobile_number) values (?,?,?)";
    mysqlConnection.query(sql, [learner.learner_name, learner.learner_email,learner.mobile_number ], (err, rows, fields) => {
        if (!err){
            console.log("New Learner added");
            var subjectArray = [];
            for(i=0;i<subjects.length;i++){ subjectArray.push([rows.insertId,subjects[i]]);  }
                console.log(subjectArray);
                var SQL2 = "INSERT INTO sub_rel_learn (learnerid, subjectid) VALUES ?";
                mysqlConnection.query(SQL2,[subjectArray],(err, rows, fields)=>{
                console.log("In relational table too added");
                mesage = 'New Learner Details added Successfully';
                console.log(rows,rows.affectedRows);
                console.log(mesage);
                res.send({data: mesage});
        })
    }else{
        console.log(err);}
    });






}// unvalid email
else{
    res.send({data:"You have entered invalid email and phone number,,..."});
}



});

/// Update operation
app.put('/update' , passport.authenticate('jwt', { session: false }) ,(req,res)=>{
    let learner = req.body;
    var subjects = learner.course_Id;
    console.log(learner);
    var sql = "UPDATE learnerdetails SET learner_name = ? , learner_email = ? , mobile_number = ? WHERE learner_id = ? ";
        mysqlConnection.query(sql,[learner.learner_name,learner.learner_email,learner.mobile_number,learner.learner_id],(err,rows,fields) => {
            if(!err){
                console.log("Learner Updates Successfully !!!");
                mysqlConnection.query("DELETE FROM sub_rel_learn WHERE learnerid = ?",[learner.learner_id],(err,rows,fields) => {
                    var subjectArray = [];
                    for(i=0;i<subjects.length;i++){ subjectArray.push([learner.learner_id,subjects[i]]);  }
                        console.log("deleted from relation and subject table");
                        console.log(subjectArray);
                    var SQL2 = "INSERT INTO sub_rel_learn (learnerid, subjectid) VALUES ?";
                    mysqlConnection.query(SQL2,[subjectArray],(err, rows, fields)=>{
                        console.log("In relational table subjects added");
                        console.log('New Learner Details updated Successfully');
                            mesage = "Learners record updated successfully..";
                            res.send({data:mesage});
            })
        });

    }else{
        console.log(err);}
    });
});

//addtime chekcing if email already exists
app.get('/email/:email', passport.authenticate('jwt', { session: false }) , (req, res) => {
    mysqlConnection.query('SELECT count(learner_email) AS totalRec FROM learnerdetails WHERE learner_email = ?',[req.params.email], (err, results, fields) => {
    if (!err){
        if(results[0].totalRec==0){ res.send({How:"No"});
            }else if(results[0].totalRec>0){ res.send({How:"Exists"});  }
        } else { //sql error
    console.log(err);}
    })
    });

//update time checking email laready exists
app.get('/upemail/:email/:id' , (req, res) => {
    mysqlConnection.query('SELECT count(learner_email) AS totalRec FROM learnerdetails WHERE learner_email = ? AND learner_id <> ?',[req.params.email,parseInt(req.params.id)], (err, results, fields) => {
    if (!err){
        if(results[0].totalRec==0){ res.send({How:"No"});
            }else if(results[0].totalRec>0){ res.send({How:"Exists"});  }
        } else { //sql error
    console.log(err);}
    })
    });


// delete data using id
app.delete('/learners/:id', passport.authenticate('jwt', { session: false }), (req, res) => {
    mysqlConnection.query("DELETE FROM sub_rel_learn WHERE learnerid = ?",[req.params.id] , (err, rows, fields) =>{
        if(!err){ console.log("Subject selection is deleted");
            mysqlConnection.query("UPDATE learnerdetails SET deleted = 1 WHERE learner_id = ?",[req.params.id] , (err, rows2, fields) =>{
                console.log("Learners and selected subjects are both record deleted successfully..");
                console.log(rows); console.log(rows2); console.log("both selection and student deleted");
                    mesage = "Learners record deleted successfully..";
                        console.log(mesage);
                        res.send({data: mesage});
        })  }
        else{
        console.log(err);}
    });
});

