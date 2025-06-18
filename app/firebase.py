import os
import firebase_admin
from firebase_admin import credentials, firestore, auth as fb_auth

cred = credentials.Certificate(os.getenv("FIREBASE_KEY_PATH", "firebase_key.json"))
firebase_admin.initialize_app(cred)

db = firestore.client()
