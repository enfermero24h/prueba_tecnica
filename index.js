const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 5000; // puerto al que nos conectamos
app.use(bodyParser.json()); // para manejar json

const tasks = []; // arreglo para las tareas
const users = []; // arreglo para los usuarios

const secretkey = "moises_key"; // llave de seguridad

// Middleware para verificar token
const autenticacion = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).json({ message: "No se proporcionó un token" });
    }
    jwt.verify(token, secretkey, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Registro de usuario 
app.post("/register", (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    const newUser = { username, password: hashedPassword };
    users.push(newUser);
    res.status(200).json({ message: 'Usuario registrado exitosamente', user: newUser });
});

// Login de usuario 
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) {
        return res.status(401).json({ message: "Usuario no encontrado" });
    }
    if (await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ username: user.username }, secretkey);
        res.status(200).json({ token });
    } else {
        res.status(401).json({ message: "Credenciales inválidas" });
    }
});

// Crear una tarea (requiere autenticación)
app.post("/tasks", autenticacion, (req, res) => {
    const { title, description } = req.body; 
    const task = { id: tasks.length + 1, title, description, username: req.user.username };
    tasks.push(task);
    res.status(201).json(task);
});

// Obtener todas las tareas del usuario autenticado
app.get("/tasks", autenticacion, (req, res) => {
    const userTasks = tasks.filter(task => task.username === req.user.username);
    res.json(userTasks);
});

// Obtener una tarea por ID
app.get("/tasks/:id", (req, res) => {
    const taskId = parseInt(req.params.id);
    const task = tasks.find(task => task.id === taskId);
    if (!task) {
        return res.status(404).json({ message: "Tarea no encontrada" });
    }
    res.json(task);
});

// Actualizar una tarea
app.put("/tasks/:id", (req, res) => {
    const taskId = parseInt(req.params.id);
    const taskIndex = tasks.findIndex(task => task.id === taskId);
    if (taskIndex === -1) {
        return res.status(404).json({ message: "Tarea no encontrada" });
    }
    const updatedTask = { ...tasks[taskIndex], ...req.body };
    tasks[taskIndex] = updatedTask;
    res.json(updatedTask);
});

// Eliminar una tarea
app.delete("/tasks/:id", (req, res) => {
    const taskId = parseInt(req.params.id);
    const taskIndex = tasks.findIndex(task => task.id === taskId);
    if (taskIndex === -1) {
        return res.status(404).json({ message: "Tarea no encontrada" });
    }
    tasks.splice(taskIndex, 1);
    res.json({ message: "Tarea eliminada" });
});

// Saludo hola mundo
app.get("/", (req, res) => {
    res.json({ message: "Hola mundo" });
});

app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
