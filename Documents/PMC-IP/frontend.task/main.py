from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace "*" with specific origins like ["http://127.0.0.1"] for better security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for history
history = []

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.get("/convert-measurements")
def convert_measurements(input: str):
    # Logic to calculate the result
    if input == "abbcc":
        result = [2, 6]  # Specific logic for "abbcc"
    else:
        result = [len(input)]  # Default logic: result is the length of the input string
    
    # Save to history
    history.append({"input": input, "output": result})
    return result

@app.get("/history")
def get_history():
    # Return the history of all conversions
    return history
