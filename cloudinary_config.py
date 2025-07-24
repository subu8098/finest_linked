import cloudinary
import os
from dotenv import load_dotenv

load_dotenv()  # Load values from .env

cloudinary.config( 
  cloud_name = os.getenv('CLOUD_NAME'),
  api_key = os.getenv('CLOUD_API_KEY'),
  api_secret = os.getenv('CLOUD_API_SECRET'),
  secure = True
)
