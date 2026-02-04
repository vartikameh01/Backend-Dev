
// word count program
const fs= require("fs");
fs.readFile("input.txt","utf8",(err,data)=>{ //asynchronous function
    if(err){
        console.log("Error reading file");
        return;
    }
    const word=data.trim().split(" ");
    const wordcount=word.length;    
    fs.writeFile("output text", `word count:${wordcount}`,(err)=>{
        if (err) {
      console.log("Error writing file");
      return;
    }
  });
});