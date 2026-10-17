
from fastapi import FastAPI 
from app import database

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


@app.get("/showdatabase_details")
def showdatabase_details():
    
    connection = database.get_connection()

    try:
        cursor = connection.cursor()
        cursor.execute("SELECT USER, SYSDATE FROM DUAL")
        result = cursor.fetchone()
        return {"Database user": result[0], "Current date": result[1]}
    except Exception as e:
        return {"Error occurred": str(e)}
    finally:
        cursor.close()
        connection.close()

