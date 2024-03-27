const express = require('express');
const { nodeAuth, authenticate, permissions } = require('node-auth-express');

const app = express();

app.use(nodeAuth({
    issuerBaseUrl: 'http://localhost:9000/oauth/v1/5xIkCPnv4X',
    baseUrl: 'http://localhost:9000',
    clientId: 'QSzqp99Ow8BIGZrHmN0mtaIInpuzhewZ',
    clientSecret: 'y4oVmZrnwkudsphu5LaNEc6sL11wBT7H',
    audience: 'http://localhost:9000'
}));

app.get('/protected', authenticate, permissions(['product:read', 'product:write']), (req, res) => {
    res.send(req.user);
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});