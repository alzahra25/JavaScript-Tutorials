from motor.motor_asyncio import AsyncIOMotorClient
from fastapi import FastAPI, HTTPException
import uvicorn
import logging
from cryptography.fernet import Fernet
import json
import os
from typing import List
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# MongoDB Configuration
MONGO_URI = "mongodb://localhost:27017"
DATABASE_NAME = "measurement_db"
COLLECTION_NAME = "measurements"

# MongoDB Client
mongo_client = None
db = None
collection = None

# Mapping of letters to numbers
alpha = {
    "_": 0, "a": 1, "b": 2, "c": 3, "d": 4, "e": 5, "f": 6, "g": 7, "h": 8, "i": 9, "j": 10,
    "k": 11, "l": 12, "m": 13, "n": 14, "o": 15, "p": 16, "q": 17, "r": 18, "s": 19,
    "t": 20, "u": 21, "v": 22, "w": 23, "x": 24, "y": 25, "z": 26 
}

app = FastAPI(title="Package Measurement API")

# Encryption setup
KEY_FILE = "encryption.key"
encryption_key = None

# File paths for RSA keys and encrypted data
PUBLIC_KEY_FILE = "public_key.pem"
PRIVATE_KEY_FILE = "private_key.pem"
ENCRYPTED_FILE = "measurements.json"

def initialize_encryption():
    """Initialize encryption key and return a Fernet instance."""
    global encryption_key
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            encryption_key = key_file.read()
    else:
        encryption_key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(encryption_key)
    return Fernet(encryption_key)

# Generate RSA Key Pair
def generate_rsa_keys():
    """Generate RSA public and private keys."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    with open(PRIVATE_KEY_FILE, "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    public_key = private_key.public_key()
    with open(PUBLIC_KEY_FILE, "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    print("RSA key pair generated and saved to files.")

# Load RSA Keys
def load_public_key():
    """Load the public key from file."""
    with open(PUBLIC_KEY_FILE, "rb") as public_file:
        return serialization.load_pem_public_key(public_file.read())

def load_private_key():
    """Load the private key from file."""
    with open(PRIVATE_KEY_FILE, "rb") as private_file:
        return serialization.load_pem_private_key(private_file.read(), password=None)

# Encrypt and Decrypt Functions
def encrypt_data(data: str) -> str:
    """Encrypt data using the public key."""
    public_key = load_public_key()
    encrypted = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted.hex()

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt data using the private key."""
    private_key = load_private_key()
    decrypted = private_key.decrypt(
        bytes.fromhex(encrypted_data),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()

@app.on_event("startup")
async def startup_event():
    """Initialize MongoDB connection and encryption."""
    global mongo_client, db, collection
    logger.info("Starting up application")
    
    # Initialize MongoDB connection
    mongo_client = AsyncIOMotorClient(MONGO_URI)
    db = mongo_client[DATABASE_NAME]
    collection = db[COLLECTION_NAME]
    logger.info("Connected to MongoDB")

    # Initialize encryption
    initialize_encryption()

    # Generate RSA keys if they don't exist
    if not os.path.exists(PUBLIC_KEY_FILE) or not os.path.exists(PRIVATE_KEY_FILE):
        generate_rsa_keys()

@app.on_event("shutdown")
async def shutdown_event():
    """Close MongoDB connection."""
    logger.info("Shutting down application")
    if mongo_client:
        mongo_client.close()
        logger.info("MongoDB connection closed")

def parse_measurements(input_str: str) -> List[int]:
    """Parse the input string into numeric values and calculate package totals."""
    logger.info(f"Processing input string: {input_str}")
    
    if not input_str:
        return []
    
    results = []
    i = 0
    while i < len(input_str):
        # 1. Determine the package size
        if input_str[i] == 'z' and i + 1 < len(input_str):
            # Combine 'z' with the next character
            if input_str[i + 1] not in alpha:
                raise ValueError(f"Invalid character after 'z': {input_str[i + 1]}")
            package_size = alpha['z'] + alpha[input_str[i + 1]]
            i += 2  # Skip both 'z' and the next character
        elif input_str[i] in alpha:
            package_size = alpha[input_str[i]]
            i += 1  # Skip the first index
        else:
            raise ValueError(f"Invalid package size character: {input_str[i]}")
        
        package_total = 0
        values_read = 0
        
        # 2. Process the next `package_size` values
        while values_read < package_size and i < len(input_str):
            current_value = 0
            # Handle 'z' combinations: sum all consecutive 'z's, then add the next character
            while i < len(input_str) and input_str[i] == 'z':
                current_value += alpha['z']
                i += 1
            if i < len(input_str):
                if input_str[i] in alpha:
                    current_value += alpha[input_str[i]]
                else:
                    raise ValueError(f"Invalid character in measurement: {input_str[i]}")
                i += 1
            package_total += current_value
            values_read += 1
        
        # 3. Fill missing values with 'a' (1) if the package size is not fully satisfied
        while values_read < package_size:
            package_total += alpha['a']
            values_read += 1
        
        results.append(package_total)
        logger.debug(f"Package total: {package_total}")
    
    return results

@app.get("/convert-measurements/")
async def convert_measurements(input: str):
    """Convert measurement string to total values and store encrypted data in a file."""
    try:
        result = parse_measurements(input)
        
        # Encrypt the input and output
        encrypted_input = encrypt_data(input)
        encrypted_output = encrypt_data(json.dumps(result))
        
        # Create a record with encrypted data
        record = {"input": encrypted_input, "output": encrypted_output}
        
        # Save the encrypted data to a file
        if os.path.exists(ENCRYPTED_FILE):
            try:
                with open(ENCRYPTED_FILE, "r") as f:
                    data = json.load(f)
            except json.JSONDecodeError:
                logger.warning(f"{ENCRYPTED_FILE} is empty or corrupted. Initializing with an empty list.")
                data = []
        else:
            data = []
        data.append(record)
        with open(ENCRYPTED_FILE, "w") as f:
            json.dump(data, f, indent=4)
        
        logger.info(f"Processed measurement: {input} -> {result} (encrypted)")
        return result
    except Exception as e:
        logger.error(f"Error processing measurement: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/decrypted-measurements/")
async def get_decrypted_measurements():
    """Retrieve decrypted measurements from the file."""
    try:
        decrypted_measurements = []
        
        # Read the encrypted data from the file
        if os.path.exists(ENCRYPTED_FILE):
            try:
                with open(ENCRYPTED_FILE, "r") as f:
                    data = json.load(f)
            except json.JSONDecodeError:
                logger.warning(f"{ENCRYPTED_FILE} is empty or corrupted. Returning an empty list.")
                data = []
        else:
            data = []
        
        for record in data:
            # Decrypt the input and output fields
            decrypted_input = decrypt_data(record["input"])
            decrypted_output = json.loads(decrypt_data(record["output"]))
            decrypted_measurements.append({
                "input": decrypted_input,
                "output": decrypted_output
            })
        
        return decrypted_measurements
    except Exception as e:
        logger.error(f"Error decrypting measurements: {e}")
        raise HTTPException(status_code=500, detail="Failed to decrypt measurements")

@app.get("/measurement-history/")
async def get_measurement_history():
    """Retrieve measurement history from MongoDB."""
    try:
        history = await collection.find().to_list(None)
        return history
    except Exception as e:
        logger.error(f"Error retrieving measurement history: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve history")

if __name__ == "__main__":
    uvicorn.run("Main_APP:app", host="0.0.0.0", port=8080, reload=False)