## NODE-AUTH-EXPRESS

<p>node-auth-express is a lightweight library designed to seamlessly integrate with the `node-auth-server`, providing a authorization middleware for your express applications.</p>

### INSTALLATION
You can install node-auth-express via npm:
```
npm install node-auth-express
```
### USAGE

<p>To integrate node-auth-express into your express application, follow these simple steps:</p>
<br/>

<b># Functions</b>

```
const { nodeAuth, authenticate, permissions } = require('node-auth-express');
```
<p><b>nodeAuth</b> - used to initialize node-auth-express</p>
<p><b>authenticate</b> - used for authenticating user identity</p>
<p><b>permissions([permissions])</b> - used to validate specific permission</p>
<p>permission receive's permission required to access api endpoint, this must be defined on node-auth-server.</p>
<br/>

<b># Configurations</b>
<p><b>issuerBaseUrl</b> - this is the authentication server url</p>
<p><b>baseUrl</b> - the base url of this application</p>
<p><b>clientId</b> - client id generated from node-auth-server</p>
<p><b>clientSecret</b> - client secret generated from node-auth-server</p>
<p><b>audience</b> - this is api domain name created on node-auth-server which represents this api (must be equivalent to baseUrl)</p>

### EXAMPLE
```
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
```
