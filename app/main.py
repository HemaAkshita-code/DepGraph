
from fastapi import FastAPI 

app = FastAPI()

@app.get("/")
def home():
    return("hey citizens!")

@app.get("/health/{bmi}")
def health(bmi: float):
    if bmi < 18.5:
            return(f"Your BMI is {bmi}. You are underweight.")
    elif bmi < 25:
        return(f"Your BMI is {bmi}. You are normal weight.")
    elif bmi >= 25 and bmi < 30:
        return(f"Your BMI is {bmi}. You are overweight.") 
    else:
         return(f"Your BMI is {bmi}. You are obese.")  
    

@app.get("/assign_task")
def assign_task():
    return({"Task": "Task x",
            "available teams" : {"a", "b"}})