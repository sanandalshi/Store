// const express = require('express');
// const crypto=require('crypto');
// const fs=require('fs');
// const pdfkit=require('pdfkit');
// const session = require('express-session');
// const MySQLStore = require('express-mysql-session')(session);
// const bodyParser = require('body-parser');
// const bcrypt = require('bcryptjs');
// const path = require('path');
// const nodemailer = require('nodemailer');
// const flash = require('connect-flash');
// const exphbs = require('express-handlebars');
// const { check, validationResult } = require('express-validator');
// const multer = require('multer');
// require('dotenv').config();
// const paypal=require('paypal-rest-sdk');
// const b = require('./models/product');
// const c = require('./models/function');
// const d = require('./models/cart');
// const db = require('./util/database');
// const isauth = require('./midleware/isauth');
// const login = require('./login');

// const app = express();

// // Setup Handlebars
// const hbs = exphbs.create({ extname: '.handlebars', defaultLayout: false });
// app.engine('handlebars', hbs.engine);
// app.set('view engine', 'ejs');
// app.set('views', path.join(__dirname, 'views'));

// const filestore = multer.diskStorage({
//   destination: (req, file, cb) => {
//     cb(null, 'images');
//   },
//   filename: (req, file, cb) => {
//     cb(null, new Date().toISOString().replace(/:/g, '-') + '-' + file.originalname);
//   }
// });
// app.use(multer({ storage: filestore }).single('image'));


// app.use(bodyParser.urlencoded({ extended: true }));
// app.use(bodyParser.json());
// app.use('/images', express.static(path.join(__dirname,'images')));

// // const options = {
// //   host: 'localhost',
// //   port: 3306,
// //   user: 'root',
// //   password: 'Wj28@krhps',
// //   database: 'node-complete'
// // };
// // const sessionStore = new MySQLStore(options);

// const options = {
//   host: process.env.DB_HOST,
//   port: process.env.DB_PORT,
//   user: process.env.DB_USER,
//   password: process.env.DB_PASSWORD,
//   database: process.env.DB_NAME
// };

// const sessionStore = new MySQLStore(options);


// // app.use(session({
// //   secret: "f4569d89189320862b20878ebaf0e660c8d409afd2a90acc3b5ed013f43af7774aeb03c4f0a4f2950ec8ede51605cd36e64a1e7e47f7789f91e566ab5e10627d",
// //   resave: false,
// //   saveUninitialized: false,
// //   store: sessionStore
// // }));

// app.use(session({
//   key: 'session_cookie_name',
//   secret: process.env.SESSION_SECRET,
//   store: sessionStore,
//   resave: false,
//   saveUninitialized: false,
//   cookie: { maxAge: 300000 }
// }));




// // app.use(session({
// //   key: 'session_cookie_name',
// //   secret: 'your-secret-key',
// //   store: sessionStore,
// //   resave: false,
// //   saveUninitialized: false,
// //   cookie: { maxAge: 300000 }
// // }));

// app.use(flash());
// app.use(login);

// const ITEMS=5;
// // let transport = nodemailer.createTransport({
// //   service: "gmail",
// //   port: 465,
// //   secure: true,
// //   auth: {
// //     user: "sanand.alshi@gmail.com",
// //     pass: "dpba pvwk psue eelk"
// //   }
// // });

// let transport = nodemailer.createTransport({
//   service: "gmail",
//   port: 465,
//   secure: true,
//   auth: {
//     user: process.env.EMAIL_USER,
//     pass: process.env.EMAIL_PASS
//   }
// });





// app.get('/', (req, res) => {
//   let session = req.session.loggedin;
//   res.render('h', { session });
// });

// app.post('/p', (req, res) => {
//   const { name, password } = req.body;
//   let obj = {
//     name: name,
//     title: 'title page',
//     body: 'bookshop near you!'
//   };
//   res.render('practise', obj);
// });

// app.post('/carti', isauth, (req, res) => {
//   const { name, password } = req.body;
//   res.send(`<h1>THE NAME OF THE CLIENT IS: ${name} AND PASSWORD IS: ${password}</h1>`);
// });

// app.post('/buy', isauth, (req, res) => {
//   let image = req.body.image;
//   let title = req.body.title;
//   res.send(`<h1>${title}</h1> <img src="${image}" alt="${title}"/>`);
// });


// app.get('/home', (req, res, next) => {
  
//    let page = parseInt(req.query.page, 10) || 1; 
//    const ITEMS = 4; 
 
//    console.log('Requested Page:', page);
 
//    if (req.session.loggedin) {
//      console.log('hai!');
//    } else {
//      console.log('nahi hai!');
//    }
 
//    let session = req.session.loggedin;
 
   
//    const offset = (page - 1) * ITEMS;

//    console.log('offest hai->:', offset); 
//    console.log('Items per Page:', ITEMS); 
//    const query = `SELECT * FROM products LIMIT ${ITEMS} OFFSET ${offset}`;
   
//    db.execute(query)
//      .then(([rows, fields]) => {
//        let products = rows.map(row => ({
//          yo: true,
//          title: row.title,
//          id: row.id,
//          image: row.imageURL,
//          price: row.price
//        }));
 
//        // Render the home page with the fetched products and session info
//        res.render('home', { products, session });
//      })
//      .catch(err => {
//        console.error('Database Error:', err); // Detailed error logging
//        res.status(500).send('Internal Server Error');
//      });
// });

// app.get('/addproduct', isauth, (req, res) => {
//   res.render('add', { mess: req.flash('mess') });
// });

// app.post('/adding', [
//   check('id').isNumeric().withMessage('ADD valid id!'),
//   check('title').isLength({ min: 3 }).withMessage("enter valid title!"),check('price').isNumeric().withMessage('Enter valid prices!')
// ], (req, res) => {
//   let idi = req.body.id.toString();
//   let ts = req.body.title.toString();
//   let price=req.body.price.toString();
//   let is = req.file;
//   if (!is) {
//     req.flash('mess', 'No file uploaded');
//     res.status(422).redirect('/addproduct');
//     return;
//   }

//   const errors = validationResult(req);
//   if (!errors.isEmpty()) {
//     console.log(errors);
//     let e = errors.array()[0].msg;
//     req.flash('mess', e);
//     res.status(422).redirect('/addproduct');
//     return;
//   }
// let url=is.path;
//   db.execute('INSERT INTO products (id, title, imageURL,price) VALUES (?, ?, ?,?)', [idi, ts, url,price])
//     .then(result => {
//       res.redirect('/');
//     })
//     .catch(err => {
//       console.log("Error:", err);
//       res.status(500).send('Internal Server Error');
//     });
// });

// app.post('/detail', (req, res) => {
//  let image=req.body.image;
//  let id=req.body.id;
// let title=req.body.title;
//   res.render('datail', {image:image,id:id,mess:req.flash('mess'),title:title});
// });
// app.get('/detail', (req, res) => {
//   let i=req.body.image;
//   let idh=req.body.id;
//  let t=req.body.title;
//    res.render('datail', {image:i,id:idh,mess:req.flash('mess'),title:t});
//  });


// let m=0;
// app.post('/cart', isauth, (req, res) => {
//   let a = req.body.id;
//   let b = req.body.title;
//   let c = req.body.image;
//   let e=req.body.quan;
//   let price=req.body.price;
 
//   d.arr.push({ id: a, title: b, image: c,quan: e,price:price});
 
//   });

// app.get('/cartarray', (req, res) => {
//   res.render('cart', {d});
// });




// app.post('/order',(req,res)=>{
//   const id = crypto.randomBytes(20).toString('hex');
//   let total=req.body.total;
//  const ans = d.arr.map(a => ({
//   id: a.id,
//   title: a.title,
//   image: a.image,
//   quan: a.quan,
  
// }));
// res.render('order', { ans ,id,total});
// });

// app.get('/order/:orderid/:total',(req,res)=>{
// const total=req.params.total
// const id = req.params.orderid;
// const invoiceName = 'invoice-' + id + '.pdf';


// res.setHeader('Content-Type', 'application/pdf');
// res.setHeader(
//   'Content-Disposition',
//   'inline; filename="' + invoiceName + '"'
// );

// const doc = new pdfkit();
// doc.pipe(res);

// let date=new Date();
// doc.fontSize(10).text(date);
// doc.fontSize(26).text('Invoice',{underline:true});
// doc.text('-----------------------------------------');
// doc.text('Your Order:');
// d.arr.forEach(a=>{
//   doc.text(a.title + '->'+ a.quan);
// })
// doc.text('total amount = ₹'+total);
// doc.text('thank you for buying from bookshop!');
// doc.end();



// })
// app.post('/delete',(req,res)=>{
//   let id=req.body.id;
//   let q = `DELETE FROM products WHERE id = ${id}`;

// db.execute(q).then((a)=>{
// if(a){
//   req.flash('mass','the product has been deleted!');
//   console.log('ho gaya delete!');
// }
// }).catch((err)=>{
//   console.log(err);
// })

// res.redirect('/home');

// })








// app.post('/logout', (req, res) => {
//   req.session.destroy(err => {
//     if (err) {
//       console.log(err);
//       return res.status(500).send('Failed to destroy session');
//     }
//     res.redirect('/');
//   });
// });

// app.get('/signin', (req, res) => {
//   let done = req.flash('done');
//   let signine = req.flash('signerror');
//   res.render('signin', { done, signine });
// });

// app.post('/valid', [
//   check('email').isEmail().withMessage('Please enter valid email!')
//     .custom(value => {
//       return db.execute('select * from user2 where email= ?', [value])
//         .then(([rows]) => {
//           if (rows.length > 0) {
//             return Promise.reject('The user already exists');
//           }
//         });
//     }),
//   check('password').isLength({ min: 5 }).withMessage('The password should contain at least 5 characters').isAlphanumeric(),
//   check('cpassword').custom((value, { req }) => {
//     if (value !== req.body.password) {
//       throw new Error('The passwords do not match');
//     }
//     return true;
//   })
// ], async (req, res) => {
//   let email = req.body.email;
//   let pass = req.body.password;
//   let cpassword = req.body.cpassword;
//   const errors = validationResult(req);
//   if (!errors.isEmpty()) {
//     let inval = errors.array()[0].msg;
//     req.flash('signerror', inval);
//     res.status(422).redirect('/signin');
//     console.log('Validation error:', errors.array());
//     return;
//   }

//   let hashedPassword = await bcrypt.hash(pass, 12);

//   db.execute('INSERT INTO user2 (email, password) VALUES (?, ?)', [email, hashedPassword])
//     .then(result => {
//       req.flash('done', 'An email has been sent to your email!');
//       res.redirect('/signin');
//       transport.sendMail({
//         to: email,
//         from: 'shopbook@gmail.com',
//         subject: 'Signup Successful',
//         html: '<h1>You have successfully signed up! Welcome to Book Shop</h1>'
//       }).then(result => { console.log('The email is sent!'); }).catch(err => { console.log(err); });
//     })
//     .catch(err => {
//       res.status(500).send('Internal Server Error');
//     });
// });

// app.use((req, res) => {
//   res.status(404).sendFile(path.join(__dirname, '404.html'));
// });

// const port = process.env.PORT || 8080;
// app.listen(port, () => {
//   console.log('Server is running on http://localhost:8080');
// });
require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');

const PDFDocument = require('pdfkit');
const session = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(session);
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const path = require('path');
const nodemailer = require('nodemailer');
const flash = require('connect-flash');
const { check, validationResult } = require('express-validator');
const multer = require('multer');
const paypal = require('paypal-rest-sdk');
const Product = require('./models/product');
const Cart = require('./models/cart');
const Order = require('./models/order');
const connectDB = require('./util/database');
const isauth = require('./midleware/isauth');
const loginRoutes = require('./login');
const User = require('./models/user');


const app = express();

// Connect to MongoDB
connectDB();

// Setup EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// File storage for uploads
// const filestore = multer.diskStorage({
//   destination: (req, file, cb) => {
//     cb(null, 'images');
//   },
//   filename: (req, file, cb) => {
//     cb(null, `${Date.now().toISOString().replace(/:/g, '-')}-${file.originalname}`);
//   },
// });
// app.use(multer({ storage: filestore }).single('image'));
// Create images directory if it doesn't exist


const imageDir = path.join(__dirname, 'images');
if (!fs.existsSync(imageDir)) {
  fs.mkdirSync(imageDir);
}


const filestore = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'images');
  },
  filename: (req, file, cb) => {
    cb(null, `${new Date().toISOString().replace(/:/g, '-')}-${file.originalname}`);
  }
});

const upload = multer({
  storage: filestore,
  fileFilter: (req, file, cb) => {
    // Optional: Restrict to images
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only images are allowed!'));
    }
  }
});
// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use('/images', express.static(path.join(__dirname, 'images')));
app.use(express.static(path.join(__dirname, 'public'))); // Serve static files
app.use(express.static('public'));

// Session store with MongoDB
const store = new MongoDBStore({
  uri: process.env.MONGO_URI,
  collection: 'sessions',
});
store.on('error', (error) => {
  console.error('Session store error:', error);
});

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store,
    cookie: {
      maxAge: 300000,
      secure: process.env.NODE_ENV === 'production', // Secure cookies in production
    },
  })
);

app.use(flash());
app.use(loginRoutes);

// Trust proxy for deployment behind load balancers
app.set('trust proxy', 1);

// Nodemailer setup
const transport = nodemailer.createTransport({
  service: 'gmail',
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});
app.use((req, res, next) => {
  res.locals.done = req.flash('done');
  res.locals.signerror = req.flash('signerror');
  res.locals.logerror = req.flash('logerror');
  res.locals.success = req.flash('success');
  next();
});
// Routes
app.get('/', (req, res) => {
  res.render('h', { session: req.session.loggedin });
});

// app.get('/home', async (req, res) => {
//   const page = parseInt(req.query.page, 10) || 1;
//   const ITEMS = 4;
//   const skip = (page - 1) * ITEMS;

//   try {
//     const products = await Product.find()
//       .skip(skip)
//       .limit(ITEMS)
//       .select('id title imageURL price')
//       .lean();
//     res.render('home', {
//       products: products.map((p) => ({ ...p, yo: true })),
//       session: req.session.loggedin,
//     });
//   } catch (error) {
//     console.error('Error fetching products:', error);
//     res.status(500).render('error', { message: 'Internal Server Error' });
//   }
// });
app.get('/home', async (req, res) => {
  const ITEMS = 4;
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const skip = (page - 1) * ITEMS;

  try {
    const totalProducts = await Product.countDocuments();
    const totalPages = Math.ceil(totalProducts / ITEMS);
    const products = await Product.find()
      .skip(skip)
      .limit(ITEMS)
      .select('id title imageURL:image price') // Rename imageURL to image
      .lean();
    res.render('home', {
      products,
     
      session: !!req.session.loggedin,
      totalPages,
      currentPage: page,
      csrfToken: typeof req.csrfToken === 'function' ? req.csrfToken() : '' // Fallback for CSRF
    });
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).render('error', {
      message: process.env.NODE_ENV === 'development' ? error.message : 'Internal Server Error'
    });
  }
});

// app.get('/addproduct', isauth, (req, res) => {
//   res.render('add', { mess: req.flash('mess') });
// });
app.get('/addproduct', isauth, (req, res) => {
  res.render('add', { mess: req.flash('mess') });
});
// app.post(
//   '/adding',
//   [
//     check('id').isNumeric().withMessage('Add valid id!'),
//     check('title').isLength({ min: 3 }).withMessage('Enter valid title!'),
//     check('price').isNumeric().withMessage('Enter valid prices!'),
//   ],
//   async (req, res) => {
//     const { id, title, price } = req.body;
//     const image = req.file;

//     if (!image) {
//       req.flash('mess', 'No file uploaded');
//       return res.status(422).redirect('/addproduct');
//     }

//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       req.flash('mess', errors.array()[0].msg);
//       return res.status(422).redirect('/addproduct');
//     }

//     try {
//       const product = new Product({
//         id: id.toString(),
//         title,
//         imageURL: image.path,
//         price: parseFloat(price),
//       });
//       await product.save();
//       console.log('product is added');
//       res.redirect('/');
//     } catch (error) {
//       console.error('Error adding product:', error);
//       res.status(500).render('error', { message: 'Internal Server Error' });
//     }
//   }
// );
app.post(
  '/adding',
  upload.single('image'), // Apply multer middleware
  [
    check('id').isNumeric().withMessage('Add valid id!'),
    check('title').isLength({ min: 3 }).withMessage('Enter valid title!'),
    check('price').isNumeric().withMessage('Enter valid prices!'),
  ],
  async (req, res) => {
    const { id, title, price } = req.body;
    const image = req.file;

    if (!image) {
      req.flash('mess', 'No file uploaded');
      return res.status(422).redirect('/addproduct');
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      req.flash('mess', errors.array()[0].msg);
      return res.status(422).redirect('/addproduct');
    }

    try {
      const product = new Product({
        id: id.toString(),
        title,
        imageURL: image.path.replace(/\\/g, '/'), // Normalize path for URLs
        price: parseFloat(price),
      });
      await product.save();
      
      console.log('Product added:', title);
      res.redirect('/');
    } catch (error) {
      console.error('Error adding product:', error);
      res.status(500).render('error', { message: 'Internal Server Error' });
    }
  }
);
app.post('/detail', (req, res) => {
  const { image, id, title } = req.body;
  res.render('datail', { image, id, mess: req.flash('mess'), title });
});

app.get('/detail', (req, res) => {
  const { image, id, title } = req.query; // Use query for GET
  res.render('datail', { image, id, mess: req.flash('mess'), title });
});

app.post('/cart', isauth, (req, res) => {
  const { id, title, image, quan, price } = req.body;
  Cart.arr.push({ id, title, image, quan: parseInt(quan), price: parseFloat(price) });
  // res.redirect('/home');
});

app.get('/cartarray', (req, res) => {
  res.render('cart', { d: Cart });
});

app.post('/order', async (req, res) => {
  const orderId = crypto.randomBytes(20).toString('hex');
  const total = parseFloat(req.body.total);
  const ans = Cart.arr.map((a) => ({
    id: a.id,
    title: a.title,
    image: a.image,
    quan: a.quan,
    price: a.price,
  }));

  try {
    const order = new Order({ orderId, items: ans, total });
    await order.save();
    res.render('order', { ans, id: orderId, total });
  } catch (error) {
    console.error('Error creating order:', error);
    res.status(500).render('error', { message: 'Internal Server Error' });
  }
});

app.get('/order/:orderid/:total', async (req, res) => {
  const { orderid, total } = req.params;
  const invoiceName = `invoice-${orderid}.pdf`;

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="${invoiceName}"`);

  const doc = new PDFDocument();
  doc.pipe(res);

  try {
    const order = await Order.findOne({ orderId: orderid }).lean();
    if (!order) {
      doc.text('Order not found');
      return doc.end();
    }

    doc.fontSize(10).text(new Date().toISOString());
    doc.fontSize(26).text('Invoice', { underline: true });
    doc.text('-----------------------------------------');
    doc.text('Your Order:');
    order.items.forEach((item) => {
      doc.text(`${item.title} -> ${item.quan}`);
    });
    doc.text(`Total amount = ₹${total}`);
    doc.text('Thank you for buying from Bookshop!');
    doc.end();
  } catch (error) {
    console.error('Error generating invoice:', error);
    doc.text('Error generating invoice');
    doc.end();
  }
});

app.post('/delete', async (req, res) => {
  const { id } = req.body;
  try {
    await Product.deleteOne({ id });
    req.flash('mess', 'The product has been deleted!');
    res.redirect('/home');
  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(500).render('error', { message: 'Internal Server Error' });
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Session destruction error:', err);
      return res.status(500).render('error', { message: 'Failed to logout' });
    }
    res.redirect('/');
  });
});

// app.get('/signin', (req, res) => {
//   res.render('signin', {
//     done: req.flash('done'),
//     signine: req.flash('signerror'),
//   });
// });
app.get('/signin', (req, res) => {
  res.render('signin', {
    done: req.flash('done'),
    signine: req.flash('signerror') // Note: This should be signerror
  });
});
// app.post(
//   '/valid',
//   [
//     check('email').isEmail().withMessage('Please enter valid email!').custom(async (value) => {
//       const user = await User.findOne({ email: value });
//       if (user) {
//         throw new Error('The user already exists');
//       }
//       return true;
//     }),
//     check('password').isLength({ min: 5 }).withMessage('The password should contain at least 5 characters').isAlphanumeric(),
//     check('cpassword').custom((value, { req }) => {
//       if (value !== req.body.password) {
//         throw new Error('The passwords do not match');
//       }
//       return true;
//     }),
//   ],
//   async (req, res) => {
//     const { email, password } = req.body;
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       req.flash('signerror', errors.array()[0].msg);
//       return res.status(422).redirect('/signin');
//     }

//     try {
//       const hashedPassword = await bcrypt.hash(password, 12);
//       const user = new User({ email, password: hashedPassword });
//       await user.save();

//       req.flash('done', 'An email has been sent to your email!');
//       res.redirect('/signin');

//       await transport.sendMail({
//         to: email,
//         from: process.env.EMAIL_USER,
//         subject: 'Signup Successful',
//         html: '<h1>You have successfully signed up! Welcome to Book Shop</h1>',
//       });
//     } catch (error) {
//       console.error('Error during signup:', error);
//       res.status(500).render('error', { message: 'Internal Server Error' });
//     }
//   }
// );
app.post(
  '/valid',
  [
    check('email')
      .isEmail()
      .withMessage('Please enter a valid email!')
      .custom(async (value) => {
        try {
          const user = await User.findOne({ email: value.toLowerCase() });
          if (user) {
            throw new Error('This email is already registered!');
          }
          return true;
        } catch (error) {
          // Log unexpected errors but rethrow validation errors
          if (error.message === 'This email is already registered!') {
            throw error;
          }
          console.error('Error in email validation:', error);
          throw new Error('An error occurred while checking the email.');
        }
      }),
    check('password')
      .isLength({ min: 5 })
      .withMessage('Password must be at least 5 characters long')
      .matches(/[a-zA-Z0-9]/)
      .withMessage('Password must contain alphanumeric characters'),
    check('cpassword').custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error('Passwords do not match!');
      }
      return true;
    })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      req.flash('signerror', errors.array()[0].msg);
      console.log('Validation errors:', errors.array());
      return res.redirect('/signin');
    }
    const { email, password } = req.body;
    try {
      const hashedPassword = await bcrypt.hash(password, 12);
      const user = new User({ email: email.toLowerCase(), password: hashedPassword });
      await user.save();
      req.flash('done', 'Account created! Please check your email.');
      console.log(`User created: ${email}`);
      await transport.sendMail({
        to: email,
        from: process.env.EMAIL_USER,
        subject: 'Welcome to Book Shop!',
        html: '<h1>You have successfully signed up! Welcome to Book Shop</h1>'
      });
      res.redirect('/signin');
    } catch (error) {
      console.error('Sign-up error:', error);
      req.flash('signerror', 'An error occurred during sign-up. Please try again.');
      res.redirect('/signin');
    }
  }
);
// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unexpected error:', err);
  res.status(500).render('error', {
    message: 'An unexpected error occurred',
    error: process.env.NODE_ENV === 'production' ? {} : err,
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, '404.html'));
});

// Start server
const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
// require('dotenv').config();
// const express = require('express');
// const crypto = require('crypto');
// const fs = require('fs');
// const PDFDocument = require('pdfkit');
// const session = require('express-session');
// const MongoDBStore = require('connect-mongodb-session')(session);
// const bodyParser = require('body-parser');
// const bcrypt = require('bcryptjs');
// const path = require('path');
// const nodemailer = require('nodemailer');
// const flash = require('connect-flash');
// const { check, validationResult } = require('express-validator');
// const multer = require('multer');
// const csurf = require('csurf'); // Added for CSRF protection
// const paypal = require('paypal-rest-sdk');
// const Product = require('./models/product');
// const Cart = require('./models/cart');
// const Order = require('./models/order');
// const connectDB = require('./util/database');
// const isauth = require('./midleware/isauth');
// const loginRoutes = require('./login');
// const User = require('./models/user');
// const app = express();

// // Connect to MongoDB
// connectDB();

// // Setup EJS
// app.set('view engine', 'ejs');
// app.set('views', path.join(__dirname, 'views'));

// // Create images directory if it doesn't exist


// // Multer setup for file uploads
// const filestore = multer.diskStorage({
//   destination: (req, file, cb) => {
//     cb(null, 'images');
//   },
//   filename: (req, file, cb) => {
//     cb(null, `${new Date().toISOString().replace(/:/g, '-')}-${file.originalname}`);
//   }
// });

// const upload = multer({
//   storage: filestore,
//   fileFilter: (req, file, cb) => {
//     if (file.mimetype.startsWith('image/')) {
//       cb(null, true);
//     } else {
//       cb(new Error('Only images are allowed!'));
//     }
//   }
// });

// // Middleware
// app.use(bodyParser.urlencoded({ extended: true }));
// app.use(bodyParser.json());
// app.use('/images', express.static(path.join(__dirname, 'images')));
// app.use(express.static(path.join(__dirname, 'public')));
// app.use(
//   session({
//     secret: process.env.SESSION_SECRET,
//     resave: false,
//     saveUninitialized: false,
//     store: new MongoDBStore({
//       uri: process.env.MONGO_URI,
//       collection: 'sessions',
//     }),
//     cookie: {
//       maxAge: 300000,
//       secure: process.env.NODE_ENV === 'production',
//     },
//   })
// );
// app.use(csurf()); // CSRF middleware
// app.use(flash());
// app.use(loginRoutes);

// // Trust proxy for deployment
// app.set('trust proxy', 1);

// // Nodemailer setup
// const transport = nodemailer.createTransport({
//   service: 'gmail',
//   port: 465,
//   secure: true,
//   auth: {
//     user: process.env.EMAIL_USER,
//     pass: process.env.EMAIL_PASS,
//   },
// });

// // Flash messages
// app.use((req, res, next) => {
//   res.locals.done = req.flash('done');
//   res.locals.signerror = req.flash('signerror');
//   res.locals.logerror = req.flash('logerror');
//   res.locals.success = req.flash('success');
//   res.locals.csrfToken = req.csrfToken(); // Add CSRF token to locals
//   next();
// });

// // Routes
// app.get('/', (req, res) => {
//   res.render('h', { session: req.session.loggedin });
// });

// app.get('/home', async (req, res) => {
//   const ITEMS = 4;
//   const page = Math.max(1, parseInt(req.query.page, 10) || 1);
//   const skip = (page - 1) * ITEMS;

//   try {
//     const totalProducts = await Product.countDocuments();
//     const totalPages = Math.ceil(totalProducts / ITEMS);
//     const products = await Product.find()
//       .skip(skip)
//       .limit(ITEMS)
//       .select('id title imageURL:image price')
//       .lean();
//     res.render('home', {
//       products,
//       session: !!req.session.loggedin,
//       totalPages,
//       currentPage: page,
//       csrfToken: req.csrfToken()
//     });
//   } catch (error) {
//     console.error('Error fetching products:', error);
//     res.status(500).render('error', {
//       message: process.env.NODE_ENV === 'development' ? error.message : 'Internal Server Error'
//     });
//   }
// });

// app.get('/addproduct', isauth, (req, res) => {
//   res.render('add', { mess: req.flash('mess'), csrfToken: req.csrfToken() });
// });

// app.post(
//   '/adding',
//   upload.single('image'), // Apply multer middleware
//   [
//     check('id').isNumeric().withMessage('Add valid id!'),
//     check('title').isLength({ min: 3 }).withMessage('Enter valid title!'),
//     check('price').isNumeric().withMessage('Enter valid prices!'),
//   ],
//   async (req, res) => {
//     const { id, title, price } = req.body;
//     const image = req.file;

//     if (!image) {
//       req.flash('mess', 'No file uploaded');
//       return res.status(422).redirect('/addproduct');
//     }

//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       req.flash('mess', errors.array()[0].msg);
//       return res.status(422).redirect('/addproduct');
//     }

//     try {
//       const product = new Product({
//         id: id.toString(),
//         title,
//         imageURL: image.path.replace(/\\/g, '/'), // Normalize path for URLs
//         price: parseFloat(price),
//       });
//       await product.save();
//       console.log('Product added:', title);
//       res.redirect('/');
//     } catch (error) {
//       console.error('Error adding product:', error);
//       res.status(500).render('error', { message: 'Internal Server Error' });
//     }
//   }
// );

// app.post('/detail', (req, res) => {
//   const { image, id, title } = req.body;
//   res.render('datail', { image, id, mess: req.flash('mess'), title, csrfToken: req.csrfToken() });
// });

// app.get('/detail', (req, res) => {
//   const { image, id, title } = req.query;
//   res.render('datail', { image, id, mess: req.flash('mess'), title, csrfToken: req.csrfToken() });
// });

// app.post('/cart', isauth, (req, res) => {
//   const { id, title, image, quan, price } = req.body;
//   Cart.arr.push({ id, title, image, quan: parseInt(quan), price: parseFloat(price) });
//   res.redirect('/cartarray');
// });

// app.get('/cartarray', (req, res) => {
//   res.render('cart', { d: Cart, csrfToken: req.csrfToken() });
// });

// app.post('/order', async (req, res) => {
//   const orderId = crypto.randomBytes(20).toString('hex');
//   const total = parseFloat(req.body.total);
//   const ans = Cart.arr.map((a) => ({
//     id: a.id,
//     title: a.title,
//     image: a.image,
//     quan: a.quan,
//     price: a.price,
//   }));

//   try {
//     const order = new Order({ orderId, items: ans, total });
//     await order.save();
//     res.render('order', { ans, id: orderId, total, csrfToken: req.csrfToken() });
//   } catch (error) {
//     console.error('Error creating order:', error);
//     res.status(500).render('error', { message: 'Internal Server Error' });
//   }
// });

// app.get('/order/:orderid/:total', async (req, res) => {
//   const { orderid, total } = req.params;
//   const invoiceName = `invoice-${orderid}.pdf`;

//   res.setHeader('Content-Type', 'application/pdf');
//   res.setHeader('Content-Disposition', `inline; filename="${invoiceName}"`);

//   const doc = new PDFDocument();
//   doc.pipe(res);

//   try {
//     const order = await Order.findOne({ orderId: orderid }).lean();
//     if (!order) {
//       doc.text('Order not found');
//       return doc.end();
//     }

//     doc.fontSize(10).text(new Date().toISOString());
//     doc.fontSize(26).text('Invoice', { underline: true });
//     doc.text('-----------------------------------------');
//     doc.text('Your Order:');
//     order.items.forEach((item) => {
//       doc.text(`${item.title} -> ${item.quan}`);
//     });
//     doc.text(`Total amount = ₹${total}`);
//     doc.text('Thank you for buying from Bookshop!');
//     doc.end();
//   } catch (error) {
//     console.error('Error generating invoice:', error);
//     doc.text('Error generating invoice');
//     doc.end();
//   }
// });

// app.post('/delete', async (req, res) => {
//   const { id } = req.body;
//   try {
//     await Product.deleteOne({ id });
//     req.flash('mess', 'The product has been deleted!');
//     res.redirect('/home');
//   } catch (error) {
//     console.error('Error deleting product:', error);
//     res.status(500).render('error', { message: 'Internal Server Error' });
//   }
// });

// app.post('/logout', (req, res) => {
//   req.session.destroy((err) => {
//     if (err) {
//       console.error('Session destruction error:', err);
//       return res.status(500).render('error', { message: 'Failed to logout' });
//     }
//     res.redirect('/');
//   });
// });

// app.get('/signin', (req, res) => {
//   res.render('signin', {
//     done: req.flash('done'),
//     signine: req.flash('signerror'),
//     csrfToken: req.csrfToken()
//   });
// });

// app.post(
//   '/valid',
//   [
//     check('email')
//       .isEmail()
//       .withMessage('Please enter a valid email!')
//       .custom(async (value) => {
//         try {
//           const user = await User.findOne({ email: value.toLowerCase() });
//           if (user) {
//             throw new Error('This email is already registered!');
//           }
//           return true;
//         } catch (error) {
//           if (error.message === 'This email is already registered!') {
//             throw error;
//           }
//           console.error('Error in email validation:', error);
//           throw new Error('An error occurred while checking the email.');
//         }
//       }),
//     check('password')
//       .isLength({ min: 5 })
//       .withMessage('Password must be at least 5 characters long')
//       .matches(/[a-zA-Z0-9]/)
//       .withMessage('Password must contain alphanumeric characters'),
//     check('cpassword').custom((value, { req }) => {
//       if (value !== req.body.password) {
//         throw new Error('Passwords do not match!');
//       }
//       return true;
//     })
//   ],
//   async (req, res) => {
//     const errors = validationResult(req);
//     if (!errors.isEmpty()) {
//       req.flash('signerror', errors.array()[0].msg);
//       console.log('Validation errors:', errors.array());
//       return res.redirect('/signin');
//     }
//     const { email, password } = req.body;
//     try {
//       const hashedPassword = await bcrypt.hash(password, 12);
//       const user = new User({ email: email.toLowerCase(), password: hashedPassword });
//       await user.save();
//       req.flash('done', 'Account created! Please check your email.');
//       console.log(`User created: ${email}`);
//       await transport.sendMail({
//         to: email,
//         from: process.env.EMAIL_USER,
//         subject: 'Welcome to Book Shop!',
//         html: '<h1>You have successfully signed up! Welcome to Book Shop</h1>'
//       });
//       res.redirect('/signin');
//     } catch (error) {
//       console.error('Sign-up error:', error);
//       req.flash('signerror', 'An error occurred during sign-up. Please try again.');
//       res.redirect('/signin');
//     }
//   }
// );

// // Error handling middleware
// app.use((err, req, res, next) => {
//   console.error('Unexpected error:', err);
//   res.status(500).render('error', {
//     message: 'An unexpected error occurred',
//     error: process.env.NODE_ENV === 'production' ? {} : err,
//   });
// });

// // 404 handler
// app.use((req, res) => {
//   res.status(404).sendFile(path.join(__dirname, '404.html'));
// });

// // Start server
// const port = process.env.PORT || 8080;
// app.listen(port, () => {
//   console.log(`Server is running on http://localhost:${port}`);
// });
