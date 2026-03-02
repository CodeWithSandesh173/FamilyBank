// ============================================
// Firebase Configuration — Family Bank
// ============================================

import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js";
import { getAuth, browserLocalPersistence, setPersistence } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js";
import { getFirestore } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-firestore.js";

const firebaseConfig = {
    apiKey: "AIzaSyCxJQ6H0KO4aSzX57P7MWDZ14b1SAXcG5o",
    authDomain: "testproject-80c39.firebaseapp.com",
    databaseURL: "https://testproject-80c39-default-rtdb.asia-southeast1.firebasedatabase.app",
    projectId: "testproject-80c39",
    storageBucket: "testproject-80c39.firebasestorage.app",
    messagingSenderId: "411741086175",
    appId: "1:411741086175:web:3c3349ad6f82cc7184246a",
    measurementId: "G-9K1YPCKV94"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// Keep user logged in across sessions
setPersistence(auth, browserLocalPersistence);

export { app, auth, db };
