import express from 'express'
import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

const router = express.Router()
const prisma = new PrismaClient()

const JWT_SECRET = process.env.JWT_SECRET


//ROTA DE CADASTRO
router.post('/cadastro', async (req,res)=>{
    try {
        
        const user = req.body

        const salt = await bcrypt.genSalt(10)
        const hashPassword = await bcrypt.hash(user.password, salt)
    

     const userDB= await prisma.user.create({
            data:{
                email: user.email,
                name: user.name,
                password: hashPassword,
            },
        })
        res.status(201).json(userDB)
  

    } catch (error) {
       
        res.status(500).json({message:"Erro no servidor, tente novamente mais tarde"})
    }
})
    


//ROTA DE LOGIN E COMPARAÇÃO COM O BANCO DE DADOS
router.post('/login', async (req,res)=>{


try {

    const {email, password} = req.body
    
    //busca usuario no bd
    const user = await prisma.user.findUnique({where:{email: email}})
    //ve se o usuario existe
    if(!user){
        return res.status(404).json({message:"usuário não encontrado"})
    }
    //compara a senha do banco com a do body
    const isMatch = await bcrypt.compare(password, user.password)

    if(!isMatch){
        return res.status(404).json({message:"Senha inválida"})
    }

    //gerar token jwt
    const token = jwt.sign({id:user.id},JWT_SECRET,{expiresIn: '1d'})
    res.status(200).json(token)

} catch (error) {
    res.status(500).json({message:"Erro no servidor, tente novamente mais tarde"})
}

})



export default router

//moisa
//Moisico2002
//mongodb+srv://moisa:<db_password>@cluster0.ndr17.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0