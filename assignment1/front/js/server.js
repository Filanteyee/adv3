const http=require('http');

const server = http.createServer((req,res) => {
    console.log('server required')
});

server.listen(3000,'localhost', (error) => {
    
})