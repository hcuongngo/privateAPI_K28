//authenticate
//authorization
const http = require('http')
const url = require('url')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')

const items = [
  { id: 1, name: 'item 1', description: 'description item 1' },
  { id: 2, name: 'item 2', description: 'description item 2' },
  { id: 3, name: 'item 3', description: 'description item 3' },
  { id: 4, name: 'item 4', description: 'description item 4' },
  { id: 5, name: 'item 5', description: 'description item 5' },
  { id: 6, name: 'item 6', description: 'description item 6' },
  { id: 7, name: 'item 7', description: 'description item 7' },
  { id: 8, name: 'item 8', description: 'description item 8' },
  { id: 9, name: 'item 9', description: 'description item 9' },
  { id: 10, name: 'item 10', description: 'description item 10' },
  { id: 11, name: 'item 11', description: 'description item 11' },
  { id: 12, name: 'item 12', description: 'description item 12' },
]

const saltRound = 10

const users = [
  { email: 'user1@gmail.com', password: bcrypt.hashSync("user1", saltRound), role: "admin" },
  { email: 'user2@gmail.com', password: bcrypt.hashSync("user2", saltRound), role: "user" },
]

const secretKey = "123"
const sampleRefreshTokens = []

const hashPassword = async (password) => {
  const saltRound = 10;
  return await bcrypt.hash(password, saltRound)
}

const comparePassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword)
}

const generateAccessToken = (email, password, role) => {
  return jwt.sign({ email, password, role }, secretKey, { expiresIn: '30m' })
}

const generateRefreshToken = (email, password, role) => {
  return jwt.sign({ email, password, role }, secretKey, { expiresIn: '7d' })
}

const register = (req, res) => {
  let body = ''
  req.on('data', (chunk) => {
    body += chunk.toString()
  })
  req.on('end', async () => {
    const newUser = JSON.parse(body)
    newUser.password = await hashPassword(newUser.password)
    users.push(newUser)
    const cloneNewUser = { ...newUser }
    delete cloneNewUser.password
    res.writeHead(201, {
      "Content-Type": "application/json"
    })
    res.end(JSON.stringify({
      message: 'Register Success',
      data: cloneNewUser
    }))
  })
}

const login = (req, res) => {
  let body = ''
  req.on('data', (chunk) => {
    body += chunk.toString()
  })
  req.on('end', async () => {
    const { email, password } = JSON.parse(body)
    const checkEmailUser = users.find(user => user.email === email)
    if (checkEmailUser) {
      const checkPasswordUser = await comparePassword(password, checkEmailUser.password)
      if (checkPasswordUser) {
        const accessToken = generateAccessToken(email, password, checkEmailUser.role)
        const refreshToken = generateRefreshToken(email, password, checkEmailUser.role)
        sampleRefreshTokens.push(refreshToken)
        const cloneUser = { ...checkEmailUser }
        delete cloneUser.password
        res.writeHead(200, {
          "Content-Type": "application/json"
        })
        res.end(JSON.stringify({
          message: 'Login Success',
          data: {
            data: cloneUser,
            accessToken,
            refreshToken,
          }
        }))
      } else {
        res.writeHead(401, {
          "Content-Type": "text/plain"
        })
        res.end("Unauthorized")
      }
    } else {
      res.writeHead(401, {
        "Content-Type": "text/plain"
      })
      res.end("Unauthorized")
    }
  })
}

const handleApiRefreshToken = (req, res) => {
  const authorizeHeader = req.headers['authorization']
  const checkRefreshTokenClient = authorizeHeader || authorizeHeader?.startsWith('Bearer ')
  if (!checkRefreshTokenClient) {
    res.writeHead(401, {
      "Content-Type": "text/plain"
    })
    res.end("Unauthorized")
    return;
  }
  const refreshToken = checkRefreshTokenClient.split(" ")[1]
  if (!refreshToken || !sampleRefreshTokens.includes(refreshToken)) {
    res.writeHead(401, {
      "Content-Type": "text/plain"
    })
    res.end("Unauthorized")
    return;
  }
  jwt.verify(refreshToken, secretKey, (err, decodedPayload) => {
    if (err) {
      res.writeHead(401, {
        "Content-Type": "text/plain"
      })
      res.end("Invalid refresh token")
      return;
    }
    console.log("decodedPayload", decodedPayload)
    const { email, password, role } = decodedPayload
    const accessToken = generateAccessToken(email, password, role)
    res.writeHead(200, {
      "Content-Type": "application/json"
    })
    res.end(JSON.stringify({
      accessToken
    }))
  })
}

const handleApiGetItems = (req, res) => {
  const parseUrl = url.parse(req.url, true)
  const path = parseUrl.pathname
  if (path === "/api/items") {
    const authorizeHeader = req.headers['authorization']
    if (!authorizeHeader || !authorizeHeader?.startsWith("Bearer ")) {
      res.writeHead(401, {
        "Content-Type": "text/plain"
      })
      res.end("Unauthorized")
      return;
    }
    const accessToken = authorizeHeader.split(" ")[1]
    jwt.verify(accessToken, secretKey, (err, decodedPayload) => {
      if (err) {
        res.writeHead(401, {
          "Content-Type": "text/plain"
        })
        res.end("Invalid access token")
        return;
      }
      res.writeHead(200, {
        "Content-Type": "application/json"
      })
      res.end(JSON.stringify({
        data: items,
        message: "Get Items Success"
      }))
    })
  } else {
    res.writeHead(404, {
      "Content-Type": "text/plain"
    })
    res.end("Not Found")
  }
}

const handleApiGetItemDetail = (req, res) => {
  const parseUrl = url.parse(req.url, true);
  const itemId = parseInt(parseUrl.pathname.split("/")[3])
  //     api/items/1  ["api", "items", "1"]
  const index = items.findIndex(item => item.id === itemId)
  if (index == -1) {
    res.writeHead(404, {
      "Content-Type": "text/plain"
    })
    res.end("Item Not Found")
    return;
  } else {
    const authorizationHeader = req.headers["authorization"]
    if (!authorizationHeader || !authorizationHeader?.startsWith("Bearer ")) {
      res.writeHead(401, {
        "Content-Type": "text/plain"
      })
      res.end("Unauthorized")
      return;
    }
    const accessToken = authorizationHeader.split(" ")[1]
    jwt.verify(accessToken, secretKey, (err, decodedPayload) => {
      if (err) {
        res.writeHead(401, {
          "Content-Type": "text/plain"
        })
        res.end("Invalid access token")
        return;
      }
      res.writeHead(200, {
        "Content-Type": "application/json"
      })
      res.end(JSON.stringify({
        data: items[index],
        message: "Get Item Detail Success"
      }))

    })
  }
}
//10 item -> 1page
//12 item -> 12 / 10 -> 1,2 
const handleApiGetItemsPagination = (req, res) => {
  const authorizationHeader = req.headers['authorization']
  if (!authorizationHeader || !authorizationHeader?.startsWith("Bearer ")) {
    res.writeHead(401, {
      "Content-Type": "text/plain"
    })
    res.end("Unauthorized");
    return;
  }
  const accessToken = authorizationHeader.split(" ")[1]
  jwt.verify(accessToken, secretKey, (err, decodedPayload) => {
    if (err) {
      res.writeHead(401, {
        "Content-Type": "text/plain"
      })
      res.end("Invalid access token")
      return;
    }
    const parseUrl = url.parse(req.url, true)
    const pageIndex = parseInt(parseUrl.query.pageIndex) || 1;
    const limit = parseInt(parseUrl.query.limit) || 10
    console.log("pageIndex", pageIndex)
    console.log("limit", limit)
    const startIndex = (pageIndex - 1) * limit
    const endIndex = startIndex + limit - 1
    let result = {
      data: items.slice(startIndex, endIndex + 1),
      itemsPerPage: limit,
      currentPageIndex: pageIndex,
      totalPages: Math.ceil(items.length / limit)
    }
    res.writeHead(200, {
      "Content-Type": "application/json"
    })
    res.end(JSON.stringify(result))
  })
}

const handleApiCreateNewItem = (req, res) => {
  let body = "";
  req.on('data', (chunk) => {
    body += chunk.toString()
  })
  req.on('end', () => {
    const authorizationHeader = req.headers['authorization']
    if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
      res.writeHead(401, {
        "Content-Type": "text/plain"
      })
      res.end("Unauthorized")
      return
    }
    // Bearer eyahsdkhad => ["Bearer", "eyhasdjhkadasd"]
    // split convert string -> array

    const accessToken = authorizationHeader.split(" ")[1]
    jwt.verify(accessToken, secretKey, (err, decodedPayload) => {
      if (err) {
        res.writeHead(401, {
          "Content-Type": "text/plain"
        })
        res.end("Invalid access token")
        return
      }
    })
  })
}



const server = http.createServer((req, res) => {
  const parseUrl = url.parse(req.url, true)
  const path = parseUrl.pathname
  const itemId = parseInt(path.split("/")[3])
  console.log("path", path)
  console.log("itemId", itemId)
  if (req.method === "POST" && path === '/api/auth/register') {
    register(req, res)
  } else if (req.method === "POST" && path === '/api/auth/login') {
    login(req, res)
  } else if (req.method === "POST" && path === '/api/auth/refresh-token') {
    handleApiRefreshToken(req, res)
  } else if (req.method === "GET" && path === '/api/items') {
    handleApiGetItems(req, res)
  } else if (req.method === "GET" && path.startsWith('/api/items/') && itemId) {
    handleApiGetItemDetail(req, res)
  } else if (req.method === "GET" && path === "/api/items/pagination") {
    handleApiGetItemsPagination(req, res)
  }
  else {
    res.writeHead(404, {
      "Content-Type": "text/plain"
    })
    res.end("Not Found")
  }
})

const PORT = 3000;
server.listen(PORT, () => {
  console.log(`Server is running at ${PORT}`)
})
