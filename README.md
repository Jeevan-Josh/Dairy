# Daily Journal

## Project Overview

Daily Journal is a personal journaling web app built with Node.js, Express, EJS, and Firebase. It allows users to create, edit, and manage private journal entries in a polished dark-themed interface.

## Key Features

- Secure sign up and login flow
- Create, read, update, and delete journal entries
- Animated dark UI with violet styling
- Firebase-backed storage for user entries

## Technologies Used
This project is built with a Node.js + Express backend and EJS views.

- Backend: Node.js and Express
- Template engine: EJS
- User authentication: bcrypt for password hashing
- Session management: express-session
- Database: Firebase Firestore via Firebase Admin SDK
- Frontend styling: custom CSS with Bootstrap on the login/signup pages
- Deployment config: Render, using render.yaml
- Form handling: Express middleware and method override for edit/delete flows

## Installation

1. Install dependencies:
   ```bash
   npm install
   ```
2. Add your Firebase service account key to `key.json`.
3. Start the app:
   ```bash
   node app.js
   ```
4. Open http://localhost:8080 in your browser.
5. Live link https://dairy-15m5.onrender.com.


## Notes

- Do not commit `key.json`; it contains sensitive Firebase credentials.
- The app is designed for learning and personal journaling.
