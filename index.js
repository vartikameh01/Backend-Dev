import express from "express"
import helmet from "helmet"
import cors from "cors"
import dotenv from "dotenv"
import router from "./employee/router/employee.route.js"


dotenv.config()
const app = express()
app.use(helmet())
app.use(cors())
app.use(express.json())

const port = process.env.PORT || 8000

app.use("/employee",router)
app.listen(port, ()=>{
    console.log("connected to the server.")
})