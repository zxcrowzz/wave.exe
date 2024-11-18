if (process.env.NODE_ENV !== "production") {
    require("dotenv").config();
}
let db;
const userFriends = {};
const users = {};
let friends = [];
let messages = {};
let peerConnection;
let name = "";
let currentFriendId = null;
const favicon = require('serve-favicon');
const multer = require('multer');
const path = require("path");
const bcrypt = require("bcrypt");
const passport = require("passport");
const LocalStrategy = require('passport-local').Strategy;
const flash = require("express-flash");
const session = require("express-session");
const mongoose = require('mongoose');
const { body, validationResult } = require('express-validator');
const User = require('./models/User');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const MongoStore = require('connect-mongo');
const https = require('https')
const express = require('express');
const app = express();
const socketio = require('socket.io');
const cookieParser = require('cookie-parser');
const rooms = {};
const router = express.Router();
let onorOff = false;
app.use(express.static(__dirname))
const ObjectId = require('mongoose').Types.ObjectId;
const { v4: uuidV4 } = require('uuid');
const Post = require('./models/post');
//we need a key and cert to run https
//we generated them with mkcert
// $ mkcert create-ca
// $ mkcert create-cert

let connectedClients = 0;
//we changed our express setup so we can use https
//pass the key and cert to createServer on https

// Create our socket.io server
const PendingUser = require('./models/PendingUser');
//create our socket.io server... it will listen to our express port
const expressServer = app.listen(process.env.PORT || 3000, () => {
    console.log(`Server running on port ${process.env.PORT || 3000}`);
});
// Create our socket.io server

//create our socket.io server... it will listen to our express port
const io = socketio(expressServer,{
    cors: {
        origin: [
            "https://localhost",
             'https://r3dxx-9ce6f110c87b.herokuapp.com' //if using a phone or another computer
        ],
        methods: ["GET", "POST"]
    }
});

//offers will contain {}
let offers = [

];
let connectedSockets = [
    
]
const connectedUsers = {};
io.on('connection',(socket)=>{
  
  
    connectedClients++;
    // console.log("Someone has connected");
    const userName = socket.handshake.auth.userName;
    const password = socket.handshake.auth.password;

    if(password !== "x"){
        socket.disconnect(true);
        return;
    }



  
    
  

    const userEmail = socket.handshake.auth.userEmail;
    
    connectedSockets.push({
        socketId: socket.id,
        userEmail
    })

    //a new client has joined. If there are any offers available,
    //emit them out
    if(offers.length){
        socket.emit('availableOffers',offers);
    }
    socket.on('message1', (messageData) => {
       
        // Broadcast the message to all connected clients
        socket.broadcast.emit('message1', messageData);
    });
  socket.on('newOffer', ({ offer, targetEmail }) => {
    // Save the offer in the offers array
    offers.push({
        offererUserName: userEmail,
        offer: offer,
        offerIceCandidates: [],
        answererUserName: targetEmail,
        answer: null,
        answererIceCandidates: []
    });

    // Print the saved offer to confirm it's added correctly
    console.log("Offer saved:", offers.slice(-1));

    // Find the socket ID for the target email
    const targetSocket = connectedSockets.find(client => client.userEmail === targetEmail);
    
    // Log the result of the target socket search
    if (targetSocket) {
        
        

        // Send offer directly to that friend
        io.to(targetSocket.socketId).emit('newOfferAwaiting', offers.slice(-1));
    } else {
       
    }
});


socket.on('sendFriendRequest',(userId,friendId)=>{

})


    socket.on('newAnswer',(offerObj,ackFunction)=>{
        
        //emit this answer (offerObj) back to CLIENT1
        //in order to do that, we need CLIENT1's socketid
        const socketToAnswer = connectedSockets.find(s=>s.userEmail === offerObj.offererUserName)
        if(!socketToAnswer){
            console.log("No matching socket")
            return;
        }
        //we found the matching socket, so we can emit to it!
        const socketIdToAnswer = socketToAnswer.socketId;
        //we find the offer to update so we can emit it
        const offerToUpdate = offers.find(o=>o.offererUserName === offerObj.offererUserName)
        if(!offerToUpdate){
            console.log("No OfferToUpdate")
            return;
        }
        //send back to the answerer all the iceCandidates we have already collected
        ackFunction(offerToUpdate.offerIceCandidates);
        offerToUpdate.answer = offerObj.answer
        offerToUpdate.answererUserName = userEmail
        //socket has a .to() which allows emiting to a "room"
        //every socket has it's own room
        socket.to(socketIdToAnswer).emit('answerResponse',offerToUpdate)
    })

    socket.on('sendIceCandidateToSignalingServer',iceCandidateObj=>{
        const { didIOffer, iceUserName, iceCandidate } = iceCandidateObj;
        // console.log(iceCandidate);
        if(didIOffer){
            //this ice is coming from the offerer. Send to the answerer
            const offerInOffers = offers.find(o=>o.offererUserName === iceUserName);
            if(offerInOffers){
                offerInOffers.offerIceCandidates.push(iceCandidate)
                // 1. When the answerer answers, all existing ice candidates are sent
                // 2. Any candidates that come in after the offer has been answered, will be passed through
                if(offerInOffers.answererUserName){
                    //pass it through to the other socket
                    const socketToSendTo = connectedSockets.find(s=>s.userEmail === offerInOffers.answererUserName);
                    if(socketToSendTo){
                        socket.to(socketToSendTo.socketId).emit('receivedIceCandidateFromServer',iceCandidate)
                    }else{
                        console.log("Ice candidate recieved but could not find answere")
                    }
                }
            }
        }else{
            //this ice is coming from the answerer. Send to the offerer
            //pass it through to the other socket
            const offerInOffers = offers.find(o=>o.answererUserName === iceUserName);
            const socketToSendTo = connectedSockets.find(s=>s.userEmail === offerInOffers.offererUserName);
            if(socketToSendTo){
                socket.to(socketToSendTo.socketId).emit('receivedIceCandidateFromServer',iceCandidate)
            }else{
                console.log("Ice candidate recieved but could not find offerer")
            }
        }
        // console.log(offers)
    })

    // Handle disconnection
    socket.on('disconnect', () => {
       

        // Remove the user's socket from connectedSockets
        connectedSockets = connectedSockets.filter(s => s.socketId !== socket.id);

        // Remove offers associated with the disconnected user
        offers = offers.filter(offer => offer.offererUserName !== userEmail && offer.answererUserName !== userEmail);
        
        // Optionally notify other users or clean up UI here if needed
    });
    

   


})

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(require('cookie-parser')());
app.set('view engine', 'ejs');
app.use(cookieParser());
app.get('/favicon.ico', (req, res) => res.status(204).end());
// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
        user: 'pantsbro4@gmail.com', // Replace with your email
        pass: 'tpxy ymac aupu ktow'   // Replace with your password
    },
    tls: {
        rejectUnauthorized: false
    }
});

// Initialize Passport
function initialize(passport) {
    const authenticateUser = async (email, password, done) => {
        try {
            const user = await User.findOne({ email });
            if (!user) {
                return done(null, false, { message: 'No user with that email' });
            }
            if (await bcrypt.compare(password, user.password)) {
                return done(null, user); // Pass the whole user object
            } else {
                return done(null, false, { message: 'Password incorrect' });
            }
        } catch (e) {
            return done(e);
        }
    };

    passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser));
    
    passport.serializeUser((user, done) => {
        done(null, user.id); // Serialize by user ID
    });

    passport.deserializeUser(async (id, done) => {
        try {
            const user = await User.findById(id);
            done(null, user); // Pass the entire user object
        } catch (err) {
            done(err, null);
        }
    });
}

initialize(passport);

// MongoDB connection
mongoose.connect('mongodb+srv://kingcod163:Saggytits101@cluster0.rcyom.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
    serverSelectionTimeoutMS: 30000
    
})

.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));
app.use('/api', router);
app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    
}));
app.use(passport.initialize());
app.use(passport.session());

// Authentication middleware
function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

function checkVerified(req, res, next) {
    
if (req.session.verificationComplete) { 
    
return next(); 

}
    
res.redirect('/verify'); 

}
async function getUserByEmail(email) {
    
    try {
        return await User.findOne({ email }).populate('friends'); // Populate friends if needed
    } catch (error) {
        console.error(`Error fetching user by email: ${email}`, error);
        return null; // Return null in case of error
    }


    
}
function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/home');
    }
    next();
}

// Register route
app.post("/register", [
    body('username').notEmpty().withMessage('Username is required'),
    body('email').isEmail().withMessage('Enter a valid email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const existingUser = await User.findOne({ email: req.body.email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already exists' });
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const token = jwt.sign({ email: req.body.email }, process.env.JWT_SECRET, { expiresIn: '1h' });

        const pendingUser = new PendingUser({
            username: req.body.username,
            email: req.body.email,
            password: hashedPassword,
            token
        });

        await pendingUser.save();

        const url = `${process.env.session_url}/confirmation/${token}`;

        await transporter.sendMail({
            to: pendingUser.email,
            subject: 'Confirm Email',
            html: `Click <a href="${url}">here</a> to confirm your email.`,
        });

        res.status(201).send('User registered. Please check your email to confirm.');
    } catch (e) {
       
        res.status(500).send('Server error');
    }
});
const messageSchema = new mongoose.Schema({
    sender: String,
    recipient: String,
    message: String,
    timestamp: { type: Date, default: Date.now }
});

const Message = mongoose.model('Message', messageSchema);
// Email confirmation
app.get('/confirmation/:token', async (req, res) => {
    try {
        const token = req.params.token;
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const pendingUser = await PendingUser.findOne({ email: decoded.email, token });

        if (!pendingUser) {
            return res.status(400).send('Invalid token or user does not exist');
        }

        const newUser = new User({
            name: pendingUser.username,
            email: pendingUser.email,
            password: pendingUser.password,
            isConfirmed: true
        });

        await newUser.save();
        await PendingUser.deleteOne({ email: pendingUser.email });

        res.send('Email confirmed. You can now log in.');
    } catch (e) {
        
        res.status(500).send('Server error');
    }
});

// Login route
app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render("login.ejs");
});



// Route for handling user login
app.post("/login", async (req, res, next) => {
    passport.authenticate('local', async (err, user, info) => {
        if (err) {
            return next(err);
        }
        if (!user) {
            return res.redirect('/login');
        }
        req.logIn(user, async (err) => {
            if (err) {
                return next(err);
            }

            const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
            req.session.verificationCode = verificationCode;

            await transporter.sendMail({
                to: user.email,
                subject: 'Your Verification Code',
                html: `<p>Your verification code is: <strong>${verificationCode}</strong></p>`,
            });

            // Set a secure cookie
            req.session.userEmail1 = req.body.email;
            // Redirect to verification page with userId as a query parameter
            return res.redirect(`/verify?userId=${user.id}`);
        });
    })(req, res, next);
});




// Verification route
app.get('/verify', (req, res) => {
    res.render('verify.ejs'); // Render your verification form here
});

// Handle verification code submission
app.post('/verify', (req, res) => {
    const { code } = req.body;

    // Check if the verification code is valid
    if (code === req.session.verificationCode) {
        // On successful verification, mark verification as complete
        req.session.verificationComplete = true;
        
        // Set the user email cookie before redirecting
        const userEmail = req.user.email;
        console.log(userEmail)
        res.cookie('userEmail', userEmail, { maxAge: 900000000, httpOnly: true, secure: true });
     
        // Redirect to insighta.html
        return res.redirect('/Untitled-1.html');
    } else {
        res.send('Invalid verification code. Please try again.');
    }
});



// Redirect root to a new room


app.post('/redirect', (req, res) => {
    res.redirect('/register');
});

// User search route
app.get('/search', async (req, res) => {
    const { name } = req.query;
    try {
        const users = await User.find({ name: new RegExp(name, 'i') }); // Case-insensitive search
        res.json(users);
    } catch (error) {
        res.status(500).send('Error searching users');
    }
});

app.post('/redirect1', (req, res) => {
    res.redirect('/login');
});

// Room route

// Registration route
app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render("register.ejs");
});




app.get('/', checkAuthenticated, checkVerified, (req, res) => { 

    res.render('Untitled-1');

});
app.get('/Untitled-1.html', checkAuthenticated, checkVerified, (req, res) => {
    res.render('Untitled-1');
});
app.post('/add-friend', checkAuthenticated, async (req, res) => {
    const { friendEmail } = req.body;

    // Validate input
    if (!friendEmail) {
        return res.status(400).send('Friend email is required.');
    }

    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).send('User not found.');
        }

        const friend = await User.findOne({ email: friendEmail });
        if (!friend) {
            return res.status(404).send('Friend not found.');
        }

        if (user.friends.includes(friend.id)) {
            return res.status(400).send('You are already friends.');
        }

        // Add friend to current user's friends list
        user.friends.push(friend.id);
        await user.save(); // Ensure this only saves the current user's document

        // Optionally, add the current user to the friend's friends list
        if (!friend.friends.includes(user.id)) {
            friend.friends.push(user.id);
            await friend.save(); // This should not cause a username validation error
        }

        res.status(200).send('Friend added successfully.');
    } catch (err) {
        console.error('Error adding friend:', err);
        res.status(500).send('Server error.');
    }
});


app.post("/api/create-post", async (req, res) => {
  const { userId, text, imgSrc, videoSrc, time, userNamez } = req.body; // Extract data from the request

  // Create a new post document
  const newPost = new Post({
    userId,
    text,
    imgSrc: imgSrc || null, // Optional field for image
    videoSrc: videoSrc || null, // Optional field for video
    time,
    userNamez,
  });

  try {
    // Save the post to the database
    const savedPost = await newPost.save();
    console.log("Post saved successfully!");

    // Return the saved post to the client (optional)
    res.json({ success: true, post: savedPost });
  } catch (error) {
    console.error("Failed to save post:", error);
    res.status(500).json({ success: false, error: "Failed to save post." });
  }
});

  


  app.get('/get-friends', async (req, res) => {
    try {
        if (!req.user || !req.user.id) {
            return res.status(401).send('Unauthorized access.');
        }

        const user = await User.findById(req.user.id)
            .populate('friends', 'name profilePicture') // Populate friends
            .populate('friends.email'); // Separate population of email

        if (!user) {
            return res.status(404).send('User not found.');
        }
         User.findOne({ }).populate('friends'); 
        const friendsList = user.friends.map(friend => ({
            name: friend.name,
            profilePicture: friend.profilePicture
                ? `data:image/png;base64,${friend.profilePicture.toString('base64')}` 
                : 'defaullt.png',
            email: friend.email, // Make sure email is included
        }));

        res.status(200).json(friendsList);
    } catch (err) {
        console.error('Error fetching friends:', err);
        res.status(500).send('Server error.');
    }
});



app.post('/send-message', checkAuthenticated, async (req, res) => {
    const { recipient, message } = req.body;

    // Input validation
    if (!recipient || !message) {
        return res.status(400).json({ message: 'Recipient and message are required.' });
    }

    const newMessage = new Message({
        sender: req.user.name,
        recipient,
        message
    });

    try {
        await newMessage.save();

        const recipientSocketId = users[recipient]; // This should now work
        if (recipientSocketId) {
            io.to(recipientSocketId).emit('message1', {
                sender: req.user.email,
                recipient,
                message
            });
        }

        res.status(200).json({ message: 'Message sent successfully!' });
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).json({ message: 'Failed to send message' });
    }
});
// Get Messages Route
app.get('/get-messages', async (req, res) => {
    const { friend, name } = req.query;

    if (!friend || !name) {
        return res.status(400).send('Friend or name is missing.');
    }

    try {
        const messages = await Message.find({
            $or: [
                { sender: friend, recipient: name },
                { sender: name, recipient: friend }
            ]
        }).sort({ timestamp: 1 });

        res.status(200).json(messages);  // Return the messages to the client
    } catch (err) {
        console.error('Error fetching messages:', err);
        res.status(500).send('Error fetching messages.');
    }
});



app.post('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            return res.status(500).json({ message: 'Failed to log out' });
        }
        req.session.destroy((err) => {
            if (err) {
                return res.status(500).json({ message: 'Failed to destroy session' });
            }
            res.clearCookie('connect.sid'); // Clear the session cookie
            res.status(200).json({ message: 'Logged out successfully' });
        });
    });
});

app.get('/get-email', async (req, res) => {
    const { userId } = req.query; // Assuming you pass userId as a query param
    try {
        const user = await User.findById(userId);
        if (user) {
            res.json({ email: user.email });
        } else {
            res.status(404).send('User not found');
        }
    } catch (error) {
        res.status(500).send('Server error');
    }
});
app.get('/api/user', async (req, res) => {
    try {
      // Use the authenticated user's ID from the session or token
      const userId = req.session.userId || req.user._id; // Adjust based on your authentication method
      const user = await User.findById(userId).select('name'); // Get only the 'name' field
  
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      res.json({ name: user.name });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Server error' });
    }
  });
app.get('/api/user/email', checkAuthenticated, async (req, res) => {
     // Log the user object
    try {
        if (!req.user) {
            return res.status(400).json({ message: 'User not authenticated' });
        }
        
        const userId = req.user._id; // Get the user's ID
        const user = await User.findById(userId).select('email');
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        res.status(200).json({ email: user.email });
    } catch (error) {
        console.error('Error retrieving user email:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
app.get('/search-users', async (req, res) => {
    const query = req.query.query; // Get the query parameter
  
    if (!query) {
      return res.json([]);
    }
  
    try {
      const users = await User.find({
        name: { $regex: query, $options: 'i' } // Case-insensitive search
      }).limit(10);  // Limit the results to a maximum of 10 users
  
      res.json(users);  // Return the users as JSON
    } catch (err) {
      console.error(err);
      res.status(500).send('Error fetching users');
    }
  });
  module.exports = router;
  app.post('/friend-request', async (req, res) => {
    try {
        const { userId, friendId } = req.body; // Assuming userId and friendId are sent in the request

        // Find the user and the friend in the database
        const user = await User.findById(userId);
        const friend = await User.findById(friendId);

        if (!user || !friend) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Check if the friend request already exists
        if (friend.friendRequests.includes(userId)) {
            return res.status(400).json({ error: 'Friend request already sent' });
        }

        // Add the user's ID to the friend's `friendRequests` array
        friend.friendRequests.push(userId);
        await friend.save();

        res.status(200).json({ message: 'Friend request sent successfully' });
    } catch (error) {
        console.error("Error sending friend request:", error);
        res.status(500).json({ error: 'An error occurred' });
    }
});



const storage = multer.memoryStorage();
const upload = multer({ 
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only images are allowed'));
    }
  }
});
app.get('/api/profile-picture', async (req, res) => {


    try {
      const userId = req.session.userId || req.user._id; // Adjust this to match your authentication system
  
      const user = await User.findById(userId).select('profilePicture');
  
      if (!user || !user.profilePicture) {
        return res.status(404).send('Profile picture not found');
      }
  
      // Set the appropriate content type (e.g., image/png or image/jpeg)
      res.contentType('image/png'); // Adjust if needed
      res.send(user.profilePicture);
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Failed to retrieve profile picture' });
    }
  });
app.post('/api/upload-profile-picture', upload.single('profilePic'), async (req, res) => {
    try {
      const userId = req.session.userId || req.user._id; // Adjust for your auth system
      const profilePicBuffer = req.file.buffer;
  
      // Save the image in MongoDB by updating the user profile
      await User.findByIdAndUpdate(userId, { profilePicture: profilePicBuffer });
  
      res.json({ message: 'Profile picture updated successfully!' });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Failed to upload profile picture' });
    }
  });


  app.get("/api/get-friend-posts", async (req, res) => {
    try {
      const currentUserId = req.session.userId || req.user._id;
  
      if (!currentUserId) {
        return res.status(400).json({ success: false, error: "User not logged in." });
      }
  
      // Get 'skip' and 'limit' query parameters (default to 0 and 10 if not provided)
      const skip = parseInt(req.query.skip) || 0;
      const limit = parseInt(req.query.limit) || 10;
  
      // Find the user and get their friends list
      const user = await User.findById(currentUserId).select('friends');
      if (!user || !user.friends) {
        return res.json({ success: true, posts: [] });
      }
  
      // Include the logged-in user's posts along with their friends' posts
      const friendIds = user.friends.map(friendId => new mongoose.Types.ObjectId(friendId));
      const userAndFriendIds = [...friendIds, currentUserId];
  
      // Fetch posts with pagination
      const posts = await Post.find({ userId: { $in: userAndFriendIds } })
        .sort({ time: -1 }) // Sort by newest first
        .skip(skip)
        .limit(limit)
        .populate('userId', 'name profilePicture'); // Populate user details
  
      // Add `canDelete` flag and profile picture to posts
      const postsWithDetails = posts.map(post => {
        const profilePicture = post.userId?.profilePicture
          ? `data:image/png;base64,${post.userId.profilePicture.toString('base64')}`
          : 'defaullt.png'; // Default profile picture
  
        const canDelete = currentUserId.toString() === post.userId._id.toString();
  
        return {
          ...post.toObject(),
          profilePicture,
          canDelete,
        };
      });
  
      res.json({ success: true, posts: postsWithDetails });
  
    } catch (error) {
      console.error("Error fetching posts:", error);
      res.status(500).json({ success: false, error: "Failed to fetch posts." });
    }
  });
  
  
  
  

  app.get('/current-user', async (req, res) => {
    const userId = req.session.userId || req.user._id;
    if (!userId) {
      return res.status(401).json({ error: 'User not authenticated' });
    }
  
    // Send back the user's ObjectId
    res.json({ userId });
  });


  app.get('/get-friend-email/:friendName', async (req, res) => {
    try {
        // Use the `friendName` parameter to find the user by name
        const friend = await User.findOne({ name: req.params.friendName }).select('email');
        
        if (!friend) {
            return res.status(404).send('Friend not found.');
        }

        // Send the friend's email as a response
        res.status(200).json({ email: friend.email });
    } catch (err) {
        res.status(500).send('Server error.');
    }
});


  app.get("/api/get-posts/:userId", async (req, res) => {
    const userId = req.session.userId || req.user._id;
  
    try {
      // Fetch posts from the database
      let posts;
      if (userId) {
        // If userId is provided, fetch posts for that specific user
        posts = await Post.find({ userId }).sort({ time: -1 }); // Sort posts by time (descending)
      } else {
        // Otherwise, fetch all posts
        posts = await Post.find().sort({ time: -1 });  // Sort posts by time (descending)
      }
  
      res.json({ success: true, posts });
    } catch (error) {
      console.error("Failed to fetch posts:", error);
      res.status(500).json({ success: false, error: "Failed to fetch posts." });
    }
  });
  app.delete('/delete-post/:postId', async (req, res) => {
    const { postId } = req.params;
  
    try {
      // Get the logged-in user ID from the session
      const currentUserId = req.session.userId || req.user._id;
  
      if (!currentUserId) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
      }
  
      // Check if the post exists and belongs to the logged-in user
      const post = await Post.findOne({ _id: postId, userId: currentUserId });
      if (!post) {
        return res.status(404).json({ success: false, error: 'Post not found or access denied' });
      }
  
      // Delete the post
      await Post.findByIdAndDelete(postId);
      res.json({ success: true, message: 'Post deleted successfully' });
    } catch (error) {
      console.error('Error deleting post:', error);
      res.status(500).json({ success: false, error: 'Internal server error' });
    }
  });
  
  
  module.exports = router;
